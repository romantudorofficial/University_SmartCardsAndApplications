package health;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class Health extends Applet {

    final static byte Health_CLA = (byte) 0x80;
    final static byte VERIFY = (byte) 0x20;

    final static byte PIN_TRY_LIMIT = (byte) 0x03;
    final static byte MAX_PIN_SIZE = (byte) 0x08;
    final static short SW_VERIFICATION_FAILED = 0x6300;

    private AESKey aesKey;
    private Cipher aesCipher;
    private OwnerPIN pin;

    private Health(byte[] bArray, short bOffset, byte bLength) {
        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);

        byte iLen = bArray[bOffset];
        bOffset = (short) (bOffset + iLen + 1);
        byte cLen = bArray[bOffset];
        bOffset = (short) (bOffset + cLen + 1);
        byte aLen = bArray[bOffset]; // lungime PIN plaintext

        // Initializare PIN
        pin.update(bArray, (short) (bOffset + 1), aLen);
        bOffset += (short)(aLen + 1);

        // Initializare cheie AES (16 bytes obligatoriu)
        aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        aesKey.setKey(bArray, bOffset);

        aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);

        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Health(bArray, bOffset, bLength);
    }

    @Override
    public boolean select() {
        return pin.getTriesRemaining() != 0;
    }

    @Override
    public void deselect() {
        pin.reset();
    }

    @Override
    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        if (apdu.isISOInterindustryCLA()) {
            if (buffer[ISO7816.OFFSET_INS] == (byte) (0xA4)) {
                return;
            }
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        if (buffer[ISO7816.OFFSET_CLA] != Health_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buffer[ISO7816.OFFSET_INS]) {
            case VERIFY:
                verify(apdu);
                return;

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void verify(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        if (dataLen != 32)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        short ivOffset = ISO7816.OFFSET_CDATA;
        short ctOffset = (short) (ivOffset + 16);

        // Decriptare AES CBC
        aesCipher.init(aesKey, Cipher.MODE_DECRYPT, buffer, ivOffset, (short) 16);
        aesCipher.doFinal(buffer, ctOffset, (short) 16, buffer, (short) 0);

        //Determina lungimea reala a PIN-ului plaintext pt ca outputul decriptarii este un Buffer cu 16 bytes
        byte pinLength = 0;
        while (pinLength < MAX_PIN_SIZE && buffer[pinLength] != 0x00)
            pinLength++;

        if (!pin.check(buffer, (short) 0, pinLength))
            ISOException.throwIt(SW_VERIFICATION_FAILED);
        // daca PIN-ul e corect nu returneaza nimic explicit (9000 automat)
        
       // Trimite PIN-ul decriptat înapoi ca raspuns APDU (pentru testare)
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 16);
        apdu.sendBytes((short) 0, (short) 16); // trimite buffer[0..pinLength-1]
    }
}
