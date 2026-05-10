package com.oracle.jcclassic.samples.wallet;

import javacard.framework.*;

public class Wallet extends Applet {

    // Pass types
    final static byte BUSPASS = (byte) 0x00;
    final static byte TRAMPASS = (byte) 0x01;
    final static byte DAYPASS = (byte) 0x02;

    // Ticket types
    final static byte BUSTICKET = (byte) 0x00;
    final static byte TRAMTICKET = (byte) 0x01;

    final static byte Wallet_CLA = (byte) 0x80;

    final static byte VERIFY = (byte) 0x20;
    final static byte CREDIT = (byte) 0x30;
    final static byte DEBIT = (byte) 0x40;
    final static byte GET_BALANCE = (byte) 0x50;
    final static byte PASS = (byte) 0x70;

    final static short MAX_BALANCE = 0x7FFF;
    final static byte MAX_TRANSACTION_AMOUNT = 127;

    final static byte PIN_TRY_LIMIT = (byte) 0x03;
    final static byte MAX_PIN_SIZE = (byte) 0x08;

    final static short SW_VERIFICATION_FAILED = 0x6300;
    final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
    final static short SW_INVALID_TRANSACTION_AMOUNT = 0x6A83;
    final static short SW_EXCEED_MAXIMUM_BALANCE = 0x6A84;
    final static short SW_NEGATIVE_BALANCE = 0x6A85;
    final static short SW_EXCEED_MAXIMUM_TICKETS = 0x6A86;
    final static short SW_BAD_TICKET_TYPE = 0x6A87;
    final static short SW_PASS_ALREADY_ACTIVE = 0x6A88;

    OwnerPIN pin;
    short balance;

    short busTrips = 0;
    short tramTrips = 0;

    boolean hasDayPass = false;

    private Wallet(byte[] bArray, short bOffset, byte bLength) {
        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);

        byte iLen = bArray[bOffset];
        bOffset += iLen + 1;
        byte cLen = bArray[bOffset];
        bOffset += cLen + 1;
        byte aLen = bArray[bOffset];

        pin.update(bArray, (short) (bOffset + 1), aLen);
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Wallet(bArray, bOffset, bLength);
    }

    public boolean select() {
        return pin.getTriesRemaining() != 0;
    }

    public void deselect() {
        pin.reset();
    }

    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        if (apdu.isISOInterindustryCLA()) {
            if (buffer[ISO7816.OFFSET_INS] == (byte) 0xA4) return;
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        if (buffer[ISO7816.OFFSET_CLA] != Wallet_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buffer[ISO7816.OFFSET_INS]) {
            case GET_BALANCE: getBalance(apdu); return;
            case DEBIT: debit(apdu); return;
            case CREDIT: credit(apdu); return;
            case VERIFY: verify(apdu); return;
            case PASS: pass(apdu); return;
            default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void credit(APDU apdu) {
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        byte amount = buffer[ISO7816.OFFSET_CDATA];

        if (amount < 0 || amount > MAX_TRANSACTION_AMOUNT) {
            ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
        }

        if ((short)(balance + amount) > MAX_BALANCE) {
            ISOException.throwIt(SW_EXCEED_MAXIMUM_BALANCE);
        }

        balance += amount;
    }

    private void debit(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        byte ticketType = buffer[ISO7816.OFFSET_P1];
        byte nTickets = buffer[ISO7816.OFFSET_P2];

        if (ticketType != BUSTICKET && ticketType != TRAMTICKET) {
            ISOException.throwIt(SW_BAD_TICKET_TYPE);
        }

        if (nTickets > 20) {
            ISOException.throwIt(SW_EXCEED_MAXIMUM_TICKETS);
        }

        // DAILY PASS FREE
        if (hasDayPass) {
            return;
        }

        // USE SUBSCRIPTION
        if (ticketType == BUSTICKET && busTrips > 0) {
            busTrips--;
            return;
        }

        if (ticketType == TRAMTICKET && tramTrips > 0) {
            tramTrips--;
            return;
        }

        byte day = buffer[ISO7816.OFFSET_CDATA];
        byte hour = buffer[ISO7816.OFFSET_CDATA + 1];

        short busPrice = 4;
        short tramPrice = 2;

        // Weekday discount (10–12)
        if (day >= 0 && day <= 4 && hour >= 10 && hour <= 11) {
            busPrice = 3;
            tramPrice = 1;
        }

        short debitAmount = 0;

        if (ticketType == BUSTICKET) {
            debitAmount = (short)(busPrice * nTickets);
        } else {
            debitAmount = (short)(tramPrice * nTickets);
        }

        // Group discount
        if (nTickets > 10) {
            debitAmount = (short)(debitAmount - debitAmount / 5);
        }

        if (debitAmount < 0 || debitAmount > MAX_TRANSACTION_AMOUNT) {
            ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
        }

        if ((short)(balance - debitAmount) < 0) {
            ISOException.throwIt(SW_NEGATIVE_BALANCE);
        }

        balance -= debitAmount;
    }

    private void pass(APDU apdu) {
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

        byte[] buffer = apdu.getBuffer();
        byte passType = buffer[ISO7816.OFFSET_P1];

        short price = 0;

        switch (passType) {

            case BUSPASS:
                if (busTrips > 0) {
                    ISOException.throwIt(SW_PASS_ALREADY_ACTIVE);
                }
                price = 60;
                break;

            case TRAMPASS:
                if (tramTrips > 0) {
                    ISOException.throwIt(SW_PASS_ALREADY_ACTIVE);
                }
                price = 40;
                break;

            case DAYPASS:
                if (hasDayPass) {
                    ISOException.throwIt(SW_PASS_ALREADY_ACTIVE);
                }
                price = 10;
                break;

            default:
                ISOException.throwIt(SW_BAD_TICKET_TYPE);
        }

        if ((short)(balance - price) < 0) {
            ISOException.throwIt(SW_NEGATIVE_BALANCE);
        }

        balance -= price;

        switch (passType) {
            case BUSPASS: busTrips = 20; break;
            case TRAMPASS: tramTrips = 30; break;
            case DAYPASS: hasDayPass = true; break;
        }
    }

    private void getBalance(APDU apdu) {
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

        byte[] buffer = apdu.getBuffer();

        apdu.setOutgoing();
        apdu.setOutgoingLength((byte)5);

        buffer[0] = (byte)(balance >> 8);
        buffer[1] = (byte)(balance);
        buffer[2] = (byte)busTrips;
        buffer[3] = (byte)tramTrips;
        buffer[4] = (byte)(hasDayPass ? 1 : 0);

        apdu.sendBytes((short)0, (short)5);
    }

    private void verify(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte read = (byte)apdu.setIncomingAndReceive();

        if (!pin.check(buffer, ISO7816.OFFSET_CDATA, read)) {
            ISOException.throwIt(SW_VERIFICATION_FAILED);
        }
    }
}