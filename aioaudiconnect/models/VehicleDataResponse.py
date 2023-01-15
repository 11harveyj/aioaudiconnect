from .Fields import Fields

class VehicleDataResponse:
    def __init__(self, data):
        self.data_fields = []
        response = data.get("StoredVehicleDataResponse")
        if response is None:
            response = data.get("CurrentVehicleDataByRequestResponse")

        vehicle_data = response.get("vehicleData")
        if vehicle_data is None:
            return

        vehicle_data = vehicle_data.get("data")
        for raw_data in vehicle_data:
            raw_fields = raw_data.get("field")
            if raw_fields is None:
                continue
            for raw_field in raw_fields:
                self.data_fields.append(Fields(raw_field))