import jakarta.jms.*;
import org.apache.qpid.jms.JmsConnectionFactory;
import org.apache.qpid.jms.JmsTopic;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;

public class AmqpExample {

    public static final String DEVICE_ID = "<device-id>";
    public static final String IOT_HUB_NAME = "<iot-hub-name>";
    public static final String POLICY_KEY = "<iot-hub-policy-key>";
    public static final String USER = "<user>";


    public static void main(String[] args) throws Exception {
        try {
            ConnectionFactory factory = new JmsConnectionFactory("amqps://" + IOT_HUB_NAME + ".azure-devices.net:5671");

            Destination queue = new JmsTopic(buildSendDestinationName(DEVICE_ID));

            Connection connection = factory.createConnection(USER,
                    generateSasToken(IOT_HUB_NAME + ".azure-devices.net", POLICY_KEY));
            connection.setExceptionListener(new MyExceptionListener());
            connection.start();

            Session session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);
            MessageProducer messageProducer = session.createProducer(queue);

            TextMessage message = session.createTextMessage("Hello world!");
            messageProducer.send(message, DeliveryMode.NON_PERSISTENT, Message.DEFAULT_PRIORITY, Message.DEFAULT_TIME_TO_LIVE);

            connection.close();
        } catch (Exception exp) {
            System.out.println("Caught exception, exiting.");
            exp.printStackTrace(System.out);
            System.exit(1);
        }
    }

    private static class MyExceptionListener implements ExceptionListener {
        @Override
        public void onException(JMSException exception) {
            System.out.println("Connection ExceptionListener fired, exiting.");
            exception.printStackTrace(System.out);
            System.exit(1);
        }
    }

    private static String buildSendDestinationName(String deviceId) {
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
