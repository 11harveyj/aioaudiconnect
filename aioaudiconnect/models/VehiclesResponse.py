from .Vehicle import Vehicle

class VehiclesResponse:
    def __init__(self, data):
        self.vehicles = []
        self.blacklisted_vins = 0
        for item in data.get("userVehicles"):
            self.vehicles.append(Vehicle(item))