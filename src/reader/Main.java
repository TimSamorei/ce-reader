package reader;

import java.io.ByteArrayInputStream;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.stream.Stream;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

public class Main {
	
	private static final byte[] AID_ANDROID = { (byte)0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
	private static final byte[] CLA_INS_P1_P2 = { 0x00, (byte)0xA4, 0x04, 0x00 };
	private static final short SW_SUCCESS = (short) 0x9000;
    private final static byte PKI_APPLET_CLA = (byte) 0x80;
    private final static byte INS_GETSIGNATURE = (byte) 0xA0;
    private final static byte INS_GETCERT = (byte) 0xB0;
    private final static byte INS_GETDATA = (byte) 0xC0;
    
    static byte[] responseData;
    static int responseLength;
    static String request;
	
    static CardChannel channel;
    
	public static void main(String[] args) {
		String alias = args[0];
		
		try {
			TerminalFactory factory = TerminalFactory.getDefault();
			CardTerminals terminals = factory.terminals();
			if (terminals.list().isEmpty()) {
				System.err.println("No smart card reders found. Connect reader and try again.");
				System.exit(1);
			}
			System.out.println("Place phone/card on reader to start");
			Card card = waitForCard(terminals);
			System.out.println("Card found");
			card.beginExclusive();
        
			try {
				// Select Applet
				channel = card.getBasicChannel();
				CommandAPDU cmd = new CommandAPDU(createSelectAidApdu(AID_ANDROID));
				ResponseAPDU response = transmit(channel, cmd);
				checkSW(response);
				
				// Generate random String to get signed
				String randomString = "Hello World!";
				
				// Send Signature Request
				request = randomString + "#" + alias;
				cmd = new CommandAPDU(PKI_APPLET_CLA, INS_GETSIGNATURE, 0x00, 0x00, request.getBytes("ASCII"));
				response = transmit(channel, cmd);
				checkSW(response);
				responseData = response.getData();
				
				// Get Signature
				responseLength = new Integer(new String(responseData));
				byte[] signature = new byte[responseLength];
				getData(signature, "signature", responseLength);
				
				// Send Certificate Request
				request = alias;
				cmd = new CommandAPDU(PKI_APPLET_CLA, INS_GETCERT, 0x00, 0x00, request.getBytes("ASCII"));
				response = transmit(channel, cmd);
				checkSW(response);
				responseData = response.getData();
				
				// Get Certificate
				responseLength = new Integer(new String(responseData));
				byte[] certificate = new byte[responseLength];
				getData(certificate, "certificate", responseLength);
				
				// Create Certificate Instance
				CertificateFactory cf = CertificateFactory.getInstance("X509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificate));
                
                // Check Signature
                Signature s = Signature.getInstance("SHA1withRSA");
                s.initVerify(cert);
                s.update(randomString.getBytes("ASCII"));
                boolean valid = s.verify(signature);
                System.out.printf("Signature is valid: %s\n", valid);
				
			} finally {
                card.endExclusive();
                card.disconnect(false);
            }
		} catch (Exception e) {
			throw new RuntimeException(e);
        }
	}
	
	private static void getData(byte[] destination, String dataType, int dataLength) {
		try {
		int counter = 0;
		CommandAPDU cmd;
		ResponseAPDU response;
		byte[] data;
		String request;
		while (responseLength > 200) {
			request = dataType + "#" + "200" + "#" + counter;
			cmd = new CommandAPDU(PKI_APPLET_CLA, INS_GETDATA, 0x00, 0x00, request.getBytes("ASCII"));
			response = transmit(channel, cmd);
			checkSW(response);
			data = response.getData();
			System.arraycopy(data, 0, destination, counter*200, 200);
			responseLength = responseLength - 200;
			counter++;
		}
		request = dataType + "#" + responseLength + "#" + counter;
		cmd = new CommandAPDU(PKI_APPLET_CLA, INS_GETDATA, 0x00, 0x00, request.getBytes("ASCII"));
		response = transmit(channel, cmd);
		checkSW(response);
		data = response.getData();
		System.arraycopy(data, 0, destination, counter*200, responseLength);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static Card waitForCard(CardTerminals terminals)
            throws CardException {
        while (true) {
            for (CardTerminal ct : terminals
                    .list(CardTerminals.State.CARD_INSERTION)) {

                return ct.connect("*");
            }
            terminals.waitForChange();
        }
    }
	
    private static ResponseAPDU transmit(CardChannel channel, CommandAPDU cmd)
            throws CardException {
    	System.out.println("APDU sent: " + toHex(cmd.getBytes()));
        ResponseAPDU response = channel.transmit(cmd);
 
        return response;
    }
    
    private static void checkSW(ResponseAPDU response) {
        if (response.getSW() != (SW_SUCCESS & 0xffff)) {
            System.err.printf("Received error status: %02X. Exiting.\n",
                    response.getSW());
            System.exit(1);
        } else {
        	logResponse(response);
        }
    }
    
    private static byte[] createSelectAidApdu(byte[] aid) {
		byte[] result = new byte[6 + aid.length];
		System.arraycopy(CLA_INS_P1_P2, 0, result, 0, CLA_INS_P1_P2.length);
		result[4] = (byte)aid.length;
		System.arraycopy(aid, 0, result, 5, aid.length);
		result[result.length - 1] = 0;
		return result;
	}
    
    private static String toHex(byte[] bytes) {
        StringBuilder buff = new StringBuilder();
        for (byte b : bytes) {
            buff.append(String.format("%02X", b));
        }

        return buff.toString();
    }

    private static void logResponse(ResponseAPDU response) {
        String swStr = String.format("%02X", response.getSW());
        byte[] data = response.getData();
        if (data.length > 0) {
            System.out.printf("APDU received: %s %s (%d)\n", toHex(data), swStr,
                    data.length);
        } else {
            System.out.printf("APDU received: %s\n", swStr);
        }
    }
}
