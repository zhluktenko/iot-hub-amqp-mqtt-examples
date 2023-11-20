import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttException;
import org.eclipse.paho.client.mqttv3.MqttMessage;
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;

public class MqttExample {

    public static final String DEVICE_ID = "<device-id>";
    public static final String IOT_HUB_NAME = "<iot-hub-name>";
    public static final String POLICY_KEY = "<iot-hub-policy-key>";

    public static void main(String[] args) {


        //String policyKey = "<iot_hub_1_key>";
        String broker = "tcp://" + IOT_HUB_NAME + ".azure-devices.net:8883";
        String topic = buildDestinationName(DEVICE_ID);
        String username = IOT_HUB_NAME + ".azure-devices.net/" + DEVICE_ID + "/?api-version=2021-04-12";
        String clientid = DEVICE_ID;
        String content = "Hello MQTT";
        int qos = 0;

        try {
            String password = generateSasToken("idun-dev-iothub-01.azure-devices.net", POLICY_KEY);
            MqttClient client = new MqttClient(broker, clientid, new MemoryPersistence());
            MqttConnectOptions options = new MqttConnectOptions();
            options.setUserName(username);
            options.setPassword(password.toCharArray());
            options.setConnectionTimeout(60);
            options.setKeepAliveInterval(60);
            // connect
            client.connect(options);
            // create message and setup QoS
            MqttMessage message = new MqttMessage(content.getBytes());
            message.setQos(qos);
            // publish message
            client.publish(topic, message);
            System.out.println("Message published");
            System.out.println("topic: " + topic);
            System.out.println("message content: " + content);
            // disconnect
            client.disconnect();
            // close client
            client.close();
        } catch (MqttException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String buildDestinationName(String deviceId) {
        return String.format("/devices/%s/messages/events", deviceId);
    }

    public static String generateSasToken(String resourceUri, String key) throws Exception {
        // Token will expire in one hour
        var expiry = Instant.now().getEpochSecond() + 3600;

        String stringToSign = URLEncoder.encode(resourceUri, StandardCharsets.UTF_8) + "\n" + expiry;
        byte[] decodedKey = Base64.getDecoder().decode(key);

        Mac sha256HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(decodedKey, "HmacSHA256");
        sha256HMAC.init(secretKey);
        Base64.Encoder encoder = Base64.getEncoder();

        String signature = new String(encoder.encode(
                sha256HMAC.doFinal(stringToSign.getBytes(StandardCharsets.UTF_8))), StandardCharsets.UTF_8);

        return "SharedAccessSignature sr=" + URLEncoder.encode(resourceUri, StandardCharsets.UTF_8)
                + "&sig=" + URLEncoder.encode(signature, StandardCharsets.UTF_8.name()) + "&se=" + expiry;
    }
}
