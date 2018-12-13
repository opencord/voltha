from voltha.adapters.openolt.openolt import OpenOltResourceMgr, OpenOltPlatform

class TellabsResourceManager(OpenOltResourceMgr):

    def __init__(self, device_id, host_and_port, extra_args, device_info):
        super(TellabsResourceManager, self).__init__(device_id, host_and_port, extra_args, device_info)

    @property
    def max_uni_id_per_onu(self):
        return OpenOltPlatform.MAX_UNIS_PER_ONU-1
