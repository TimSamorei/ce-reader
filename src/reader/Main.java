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
    private final static byte INS_VERIFY = (byte) 0xA0;
    private final static byte INS_GETCERT = (byte) 0xA1;
    private final static byte INS_GETCERT2 = (byte) 0xA2;
	
	public static void main(String[] args) {
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
				CardChannel channel = card.getBasicChannel();
				CommandAPDU cmd = new CommandAPDU(createSelectAidApdu(AID_ANDROID));
				ResponseAPDU response = transmit(channel, cmd);
				checkSW(response);
				
				String randomString = "Hello World!";
				System.out.println("String to Verify: " + randomString);
				System.out.println("Bytes to Verify: " + Arrays.toString(randomString.getBytes("ASCII")));
				
				cmd = new CommandAPDU(PKI_APPLET_CLA, INS_VERIFY, 0x00, 0x00, randomString.getBytes("ASCII"));
				response = transmit(channel, cmd);
				checkSW(response);
				byte[] signature = response.getData();
				System.out.printf("Got signature from card(HEX): %s\n", toHex(signature));
				System.out.printf("Got signature from card(String): %s\n", new String(signature));
				
				String alias = "alias 1";
				System.out.println("Alias (String): " + alias);
				System.out.println("Alias (Bytes): " + Arrays.toString(alias.getBytes("ASCII")));
				cmd = new CommandAPDU(PKI_APPLET_CLA, INS_GETCERT, 0x00, 0x00, alias.getBytes("ASCII"));
				response = transmit(channel, cmd);
				checkSW(response);
				byte[] certBlob1 = response.getData();
				
				cmd = new CommandAPDU(PKI_APPLET_CLA, INS_GETCERT2, 0x00, 0x00, alias.getBytes("ASCII"));
				response = transmit(channel, cmd);
				checkSW(response);
				byte[] certBlob2 = response.getData();
				
				byte[] certBlob = Arrays.copyOf(certBlob1, certBlob1.length + certBlob2.length);
				System.arraycopy(certBlob2, 0, certBlob, certBlob1.length, certBlob2.length);
				
				System.out.printf("Got cert from card(HEX): %s\n", toHex(certBlob));
				System.out.printf("Got cert from card(String): %s\n", new String(certBlob));
				
				CertificateFactory cf = CertificateFactory.getInstance("X509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBlob));
                
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
    
    public static String toHex(byte[] bytes) {
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
