class SystemInit:
    def __init__(self):
        self.ip_cidr = {"lo":"127.0.0.1/24"}
        self.gateway = {"lo":"127.0.0.1"}
        self.nameservers = ["1.1.1.1"]
        self.hostname = {"hostname":"OperationsHost1","FQDN":"OperationsHost1.localnet.net"}
        self.autoinit = False
        self.autoip = False
        self.mac = "00:00:00:00:00:00"
        self.os = {"Family":"linux","Version":"rhel"}

    def SetupNetwork(self, osinfo):
        from subprocess import call
        if type(osinfo) is not dict or len(osinfo) > 4:
            return False
        if osinfo["Family"] == "rhel":
            call("sudo ip addr add %s dev %")
        elif osinfo["Family"] == "linux":

        elif osinfo["Family"] == "windows":
            call("")
        elif osinfo["Family"] == "OSX":
            # TODO: Build OSX management
            return False
        else:
            return False


    def DetectOs(self):
        import platform
        self.os["Family"] = platform.system()
        version = platform.version()
        if "ubuntu" in version:
            version = "ubuntu"
        elif "debian" in version:
            version = "debian"
        elif "SMP" in "rhel":
            version = "rhel"
        else:
            version = "Not Found"
        self.os["Version"] = version
        return True