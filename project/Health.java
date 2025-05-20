package health;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class Health extends Applet {

    // CLA and INS
    final static byte Health_CLA = (byte) 0x80;
    final static byte VERIFY = (byte) 0x20;
    final static byte INS_UPDATE_PIN          = (byte) 0x24;
    final static byte INS_GET_PATIENT_DATA    = (byte) 0x30;
    final static byte INS_SET_PATIENT_DATA    = (byte) 0x40;
    final static byte INS_SET_CONSULT_DATA    = (byte) 0x50;
    final static byte INS_SET_MED_VACATION    = (byte) 0x60;

    // Status words
    final static short SW_VERIFICATION_FAILED = 0x6300;
    final static short SW_NOT_ENOUGH_DATA     = 0x6A80;
    final static short SW_CONDITIONS_NOT_SATISFIED = 0x6985;

    // PIN parameters
    final static byte PIN_TRY_LIMIT = (byte) 0x03;
    final static byte MAX_PIN_SIZE  = (byte) 0x08;

    private AESKey aesKey;
    private Cipher aesCipher;
    private OwnerPIN pin;

    // Persistent storage for patient data
    // Layout:
    // [0..2]   birthDate (3)
    // [3]      bloodGroup
    // [4]      rh
    // [5]      chronicDiagnosticCode
    // [6]      chronicSpecialtyCode
    // [7]      donorFlag
    // [8..(8+8*3-1)]  3 consults: each (diag(1), spec(1), date(3)) => 5 bytes each, total 15 bytes
    // [23..25]  vacationStart (3)
    // [26..28]  vacationEnd   (3)
    private byte[] patientData;

    private Health(byte[] bArray, short bOffset, byte bLength) {
        // Initialize PIN
        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
        byte pinLen = bArray[(short)(bOffset)];
        pin.update(bArray, (short)(bOffset+1), pinLen);
        // Skip to AES key
        short aesKeyOffset = (short)(bOffset + 1 + pinLen);
        aesKey = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        aesKey.setKey(bArray, aesKeyOffset);
        aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);

        // Allocate persistent patient data
        patientData = new byte[29];

        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Health(bArray, bOffset, bLength);
    }

    @Override
    public boolean select() {
        return pin.getTriesRemaining() > 0;
    }

    @Override
    public void deselect() {
        pin.reset();
    }

    @Override
    public void process(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        if (selectingApplet()) return;

        if (buf[ISO7816.OFFSET_CLA] != Health_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buf[ISO7816.OFFSET_INS]) {
            case VERIFY:
                verify(apdu);
                break;
            case INS_UPDATE_PIN:
                requireVerified();
                updatePin(apdu);
                break;
            case INS_GET_PATIENT_DATA:
                requireVerified();
                getPatientData(apdu);
                break;
            case INS_SET_PATIENT_DATA:
                requireVerified();
                setPatientData(apdu);
                break;
            case INS_SET_CONSULT_DATA:
                requireVerified();
                setConsultData(apdu);
                break;
            case INS_SET_MED_VACATION:
                requireVerified();
                setMedicalVacation(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void requireVerified() {
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_VERIFICATION_FAILED);
        }
    }

    /*** INS implementations ***/

    // VERIFY: decrypt and check PIN
    private void verify(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        if (len != 32) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short ivOffset = ISO7816.OFFSET_CDATA;
        short ctOffset = (short)(ivOffset+16);
        // decrypt
        aesCipher.init(aesKey, Cipher.MODE_DECRYPT, buffer, ivOffset, (short)16);
        aesCipher.doFinal(buffer, ctOffset, (short)16, buffer, (short)0);
        // obtain PIN length
        byte pinLen=0;
        while(pinLen<MAX_PIN_SIZE && buffer[pinLen]!=0) pinLen++;
        if (!pin.check(buffer, (short)0, pinLen)) ISOException.throwIt(SW_VERIFICATION_FAILED);
        // success
    }

    // UPDATE PIN: expects plaintext old PIN and new PIN as two 8-byte fields
    private void updatePin(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        if (len < (short)(MAX_PIN_SIZE*2)) ISOException.throwIt(SW_NOT_ENOUGH_DATA);
        // check existing PIN
        if (!pin.check(buf, ISO7816.OFFSET_CDATA, MAX_PIN_SIZE)) ISOException.throwIt(SW_VERIFICATION_FAILED);
        // update to new PIN
        pin.update(buf, (short)(ISO7816.OFFSET_CDATA+MAX_PIN_SIZE), MAX_PIN_SIZE);
    }

    // GET PATIENT DATA: return full patientData
    private void getPatientData(APDU apdu) {
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)patientData.length);
        apdu.sendBytesLong(patientData, (short)0, (short)patientData.length);
    }

    // SET PATIENT DATA: P1 selects field: 0=chronic diag,1=chronic spec,2=donor
    private void setPatientData(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        byte option = buf[ISO7816.OFFSET_P1];
        byte value = buf[ISO7816.OFFSET_CDATA];
        switch(option) {
            case 0: patientData[5] = value; break;
            case 1: patientData[6] = value; break;
            case 2: patientData[7] = value; break;
            default: ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    // SET CONSULT DATA: P1=diagnostic code, P2=specialty code, data: date(3bytes)
    private void setConsultData(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        byte diag = buf[ISO7816.OFFSET_P1];
        byte spec = buf[ISO7816.OFFSET_P2];
        if (len!=3) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        byte d0=buf[ISO7816.OFFSET_CDATA], d1=buf[ISO7816.OFFSET_CDATA+1], d2=buf[ISO7816.OFFSET_CDATA+2];
        // eligibility check
        boolean chronicMatch = (patientData[5]!=0 && patientData[6]==spec);
        boolean newMonth = true; // TODO: implement month check
        if (!(chronicMatch || (patientData[5]==0 && newMonth))) ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
        // shift oldest consult
        Util.arrayCopy(patientData, (short)13, patientData, (short)8, (short)10);
        // insert new at end
        short pos = (short)(8+10);
        patientData[pos]   = diag;
        patientData[(short)(pos+1)] = spec;
        patientData[(short)(pos+2)] = d0;
        patientData[(short)(pos+3)] = d1;
        patientData[(short)(pos+4)] = d2;
    }

    // SET MEDICAL VACATION: data 6 bytes start(3) and end(3)
    private void setMedicalVacation(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        if (len!=6) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        // eligibility
        boolean chronic = (patientData[5]!=0);
        boolean withinLimit = true; // TODO: implement days count this month
        if (!(chronic || (!chronic && withinLimit))) ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
        // store
        Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, patientData, (short)23, (short)6);
    }
}
