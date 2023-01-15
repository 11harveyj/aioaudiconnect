class TripDataResponse:
    def __init__(self, data):
        self.data_fields = []

        self.tripID = data["tripID"]

        self.averageElectricEngineConsumption = None
        if "averageElectricEngineConsumption" in data:
             self.averageElectricEngineConsumption = float(data["averageElectricEngineConsumption"]) / 10

        self.averageFuelConsumption = None
        if "averageFuelConsumption" in data:
            self.averageFuelConsumption = float(data["averageFuelConsumption"]) / 10

        self.averageSpeed = None
        if "averageSpeed" in data:
            self.averageSpeed = int(data["averageSpeed"])

        self.mileage = None
        if "mileage" in data:
            self.mileage = int(data["mileage"])

        self.startMileage = None
        if "startMileage" in data:
            self.startMileage = int(data["startMileage"])

        self.traveltime = None
        if "traveltime" in data:
            self.traveltime = int(data["traveltime"])

        self.timestamp = None
        if "timestamp" in data:
            self.timestamp = data["timestamp"]

        self.overallMileage = None
        if "overallMileage" in data:
            self.overallMileage = int(data["overallMileage"])