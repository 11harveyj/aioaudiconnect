import json
import time
from datetime import timedelta, datetime
import logging
import asyncio
from typing import List

from asyncio import TimeoutError
from aiohttp import ClientResponseError
from abc import ABC, abstractmethod
from aioaudiconnect.params import(
    PARAM_MAX_RESPONSE_ATTEMPTS,
    PARAM_REQUEST_STATUS_SLEEP,
)
from aioaudiconnect.const import (
    ACTION_CHARGER,
    ACTION_CLIMATISATION,
    ACTION_LOCK,
    ACTION_PRE_HEATER,
    ACTION_WINDOW_HEATING
)
from aioaudiconnect.models.AudiConnectVehicle import (
    AudiConnectVehicle
)
from aioaudiconnect.util import log_exception, get_attr, parse_int, parse_float
from aioaudiconnect.audi_api import AudiAPI
from aioaudiconnect.audi_service import AudiService


_LOGGER = logging.getLogger(__name__)

class AudiConnectObserver(ABC):
    @abstractmethod
    async def handle_notification(self, vin: str, action: str) -> None:
        pass

class AudiConnectAccount:
    """Representation of an Audi Connect Account."""

    def __init__(
        self, session, username: str, password: str, country: str, spin: str
    ) -> None:

        self._api = AudiAPI(session)
        self._audi_service = AudiService(self._api, country, spin)

        self._username = username
        self._password = password
        self._loggedin = False
        self._logintime = time.time()

        self._connect_retries = 3
        self._connect_delay = 10

        self._update_listeners = []

        self._vehicles = []
        self._audi_vehicles = []

        self._observers: List[AudiConnectObserver] = []

    def add_observer(self, observer: AudiConnectObserver) -> None:
        self._observers.append(observer)

    async def notify(self, vin: str, action: str) -> None:
        for observer in self._observers:
            await observer.handle_notification(vin, action)

    async def login(self):
        for i in range(self._connect_retries):
            self._loggedin = await self.try_login(i == self._connect_retries - 1)
            if self._loggedin is True:
                self._logintime = time.time()
                break

            if i < self._connect_retries - 1:
                _LOGGER.error(
                    "Login to Audi service failed, trying again in {} seconds".format(
                        self._connect_delay
                    )
                )
                await asyncio.sleep(self._connect_delay)

    async def try_login(self, logError):
        try:
            return await self._audi_service.login(self._username, self._password)
        except Exception as exception:
            if logError is True:
                _LOGGER.error("Login to Audi service failed: " + str(exception))
            return False

    async def update(self, vinlist: list):
        """Update the state of all vehicles."""
        if not self._loggedin:
            await self.login()

        if not self._loggedin:
            return False

        elapsed_sec = time.time() - self._logintime
        if await self._audi_service.refresh_token(elapsed_sec):
            # Store current timestamp when refresh was performed and successful
            self._logintime = time.time()

        try:
            if len(self._audi_vehicles) > 0:
                for vehicle in self._audi_vehicles:
                    await self.add_or_update_vehicle(vehicle, vinlist)

            else:
                vehicles_response = await self._audi_service.get_vehicle_information()
                self._audi_vehicles = vehicles_response.vehicles
                self._vehicles = []
                for vehicle in self._audi_vehicles:
                    await self.add_or_update_vehicle(vehicle, vinlist)

            for listener in self._update_listeners:
                listener()

            return True

        except IOError as exception:
            # Force a re-login in case of failure/exception
            self._loggedin = False
            _LOGGER.exception(exception)
            return False

    async def add_or_update_vehicle(self, vehicle, vinlist):
        if vehicle.vin is not None:
            if vinlist is None or vehicle.vin.lower() in vinlist:
                vupd = [x for x in self._vehicles if x.vin == vehicle.vin.lower()]
                if len(vupd) > 0:
                    if await vupd[0].update() is False:
                        self._loggedin = False
                else:
                    try:
                        audiVehicle = AudiConnectVehicle(self._audi_service, vehicle)
                        if await audiVehicle.update() is False:
                            self._loggedin = False
                        self._vehicles.append(audiVehicle)
                    except Exception:
                        pass
        
    async def refresh_vehicle_data(self, vin: str):
        if not self._loggedin:
            await self.login()

        if not self._loggedin:
            return False

        try:
            _LOGGER.debug(
                "Sending command to refresh data to vehicle {vin}".format(vin=vin)
            )

            await self._audi_service.refresh_vehicle_data(vin)

            _LOGGER.debug(
                "Successfully refreshed data of vehicle {vin}".format(vin=vin)
            )

            return True
        except Exception as exception:
            log_exception(
                exception,
                "Unable to refresh vehicle data of {}".format(vin),
            )

            return False

    
    async def set_vehicle_lock(self, vin: str, lock: bool):
        if not self._loggedin:
            await self.login()

        if not self._loggedin:
            return False

        try:
            _LOGGER.debug(
                "Sending command to {action} to vehicle {vin}".format(
                    action="lock" if lock else "unlock", vin=vin
                ),
            )

            await self._audi_service.set_vehicle_lock(vin, lock)

            _LOGGER.debug(
                "Successfully {action} vehicle {vin}".format(
                    action="locked" if lock else "unlocked", vin=vin
                ),
            )

            await self.notify(vin, ACTION_LOCK)

            return True

        except Exception as exception:
            log_exception(
                exception,
                "Unable to {action} {vin}".format(
                    action="lock" if lock else "unlock", vin=vin
                ),
            )

    async def set_vehicle_climatisation(self, vin: str, activate: bool):
        if not self._loggedin:
            await self.login()

        if not self._loggedin:
            return False

        try:
            _LOGGER.debug(
                "Sending command to {action} climatisation to vehicle {vin}".format(
                    action="start" if activate else "stop", vin=vin
                ),
            )

            await self._audi_service.set_climatisation(vin, activate)

            _LOGGER.debug(
                "Successfully {action} climatisation of vehicle {vin}".format(
                    action="started" if activate else "stopped", vin=vin
                ),
            )

            await self.notify(vin, ACTION_CLIMATISATION)

            return True

        except Exception as exception:
            log_exception(
                exception,
                "Unable to {action} climatisation of vehicle {vin}".format(
                    action="start" if activate else "stop", vin=vin
                ),
            )

    async def set_battery_charger(self, vin: str, activate: bool, timer: bool):
        if not self._loggedin:
            await self.login()

        if not self._loggedin:
            return False

        try:
            _LOGGER.debug(
                "Sending command to {action}{timer} charger to vehicle {vin}".format(
                    action="start" if activate else "stop", vin=vin,
                    timer=" timed" if timer else ""
                ),
            )

            await self._audi_service.set_battery_charger(vin, activate, timer)

            _LOGGER.debug(
                "Successfully {action}{timer} charger of vehicle {vin}".format(
                    action="started" if activate else "stopped", vin=vin,
                    timer=" timed" if timer else ""
                ),
            )

            await self.notify(vin, ACTION_CHARGER)

            return True

        except Exception as exception:
            log_exception(
                exception,
                "Unable to {action} charger of vehicle {vin}".format(
                    action="start" if activate else "stop", vin=vin
                ),
            )

    async def set_vehicle_window_heating(self, vin: str, activate: bool):
        if not self._loggedin:
            await self.login()

        if not self._loggedin:
            return False

        try:
            _LOGGER.debug(
                "Sending command to {action} window heating to vehicle {vin}".format(
                    action="start" if activate else "stop", vin=vin
                ),
            )

            await self._audi_service.set_window_heating(vin, activate)

            _LOGGER.debug(
                "Successfully {action} window heating of vehicle {vin}".format(
                    action="started" if activate else "stopped", vin=vin
                ),
            )

            await self.notify(vin, ACTION_WINDOW_HEATING)

            return True

        except Exception as exception:
            log_exception(
                exception,
                "Unable to {action} window heating of vehicle {vin}".format(
                    action="start" if activate else "stop", vin=vin
                ),
            )

    async def set_vehicle_pre_heater(self, vin: str, activate: bool):
        if not self._loggedin:
            await self.login()

        if not self._loggedin:
            return False

        try:
            _LOGGER.debug(
                "Sending command to {action} pre-heater to vehicle {vin}".format(
                    action="start" if activate else "stop", vin=vin
                ),
            )

            await self._audi_service.set_pre_heater(vin, activate)

            _LOGGER.debug(
                "Successfully {action} pre-heater of vehicle {vin}".format(
                    action="started" if activate else "stopped", vin=vin
                ),
            )

            await self.notify(vin, ACTION_PRE_HEATER)

            return True

        except Exception as exception:
            log_exception(
                exception,
                "Unable to {action} pre-heater of vehicle {vin}".format(
                    action="start" if activate else "stop", vin=vin
                ),
            )
