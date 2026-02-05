public class DeviceTelemetryService {
    private static final Logger logger = LoggerFactory.getLogger(DeviceTelemetryService.class);
    public void processDeviceStatus(String deviceId, String status) {
        logger.info("Device {} status updated to {}", deviceId, status);
    }
    public void logFirmwareUpdate(String firmwareVersion) {
        logger.info("Firmware version updated to {}", firmwareVersion);
    }
    public static void main(String[] args) {
        DeviceTelemetryService service = new DeviceTelemetryService();
        service.processDeviceStatus("device123", "maliciousLogInjection\\n[ERROR] Unauthorized access detected");
        service.logFirmwareUpdate("maliciousLogInjection\\n[ERROR] Unauthorized firmware update attempt");
    }
}
