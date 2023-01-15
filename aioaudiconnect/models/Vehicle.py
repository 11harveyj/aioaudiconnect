class Vehicle:
    def __init__(self, data):
        self.vin = ""
        self.csid = ""
        self.model = ""
        self.model_year = ""
        self.model_family = ""
        self.title = ""

        self.vin = data.get("vin")
        self.csid = data.get("csid")
        if data.get("vehicle") is not None and data.get("vehicle").get("media") is not None:
            self.model = data.get("vehicle").get("media").get("longName")
        if data.get("vehicle") is not None and data.get("vehicle").get("core") is not None:
            self.model_year = data.get("vehicle").get("core").get("modelYear")
        if data.get("nickname") is not None and len(data.get("nickname")) > 0:
            self.title = data.get("nickname")
        elif data.get("vehicle") is not None and data.get("vehicle").get("media") is not None:
            self.title = data.get("vehicle").get("media").get("shortName")

    def __str__(self):
        return str(self.__dict__)