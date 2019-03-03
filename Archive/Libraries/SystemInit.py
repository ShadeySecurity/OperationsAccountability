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
        self.netconf = {"lo":"/etc/sysconfig/network-scipts/ifcfg-lo"}

    def SetupNetwork(self, osinfo):
        if type(osinfo) is not dict or len(osinfo) > 4:
            return False
        if osinfo["Family"] == "linux":

        elif osinfo["Family"] == "windows":

        elif osinfo["Family"] == "osx":


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