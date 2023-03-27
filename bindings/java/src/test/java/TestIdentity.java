import enums.NpStatus;
import helper.TestHelper;
import models.NeuropilNode;
import models.NpToken;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class TestIdentity {


    private static NpToken np1Ident;
    private static NpToken np2Ident;

    private static boolean checkNp1IdentOk = false;
    private static boolean checkNp2IdentOk = false;

    @Test
    public void identityTest() throws NoSuchMethodException {

        NeuropilNode np1 = new NeuropilNode(4001, false, "logs/smoke_test_identity_nl1.log");
        NeuropilNode np2 = new NeuropilNode(4002, false, "logs/smoke_test_identity_nl2.log");

        np2Ident = np2.newIdentity();
        np2.useIdentity(np2Ident);
        TestHelper.disableAAA(np2);
        np2.setAuthenticateCb(TestIdentity.class.getDeclaredMethod("authzAllowAllCheckIdent1", NeuropilNode.class,
                NpToken.class));
        np2.run(0);

        np1Ident = np1.newIdentity();
        np1.useIdentity(np1Ident);
        TestHelper.disableAAA(np1);
        np1.setAuthenticateCb(TestIdentity.class.getDeclaredMethod("authzAllowAllCheckIdent2", NeuropilNode.class,
                NpToken.class));
        np1.run(0);

        String np1Addr = np1.getAddress();
        String np2Addr = np2.getAddress();

        np2.join(np1Addr);
        np1.join(np2Addr);

        int timeout = 60;

        Double t1 = System.currentTimeMillis()/1000.0;
        Double elapsed = 0.;

        try{
            while(elapsed < timeout){
                elapsed = (System.currentTimeMillis()/1000.0) - t1;

                Double mod = elapsed / 2;
                if(mod == 0){
                    Assertions.assertTrue(np1.getStatus() == NpStatus.NP_RUNNING.intValue());
                    Assertions.assertTrue(np2.getStatus() == NpStatus.NP_RUNNING.intValue());
                }

                if (checkNp1IdentOk && checkNp2IdentOk)
                    break;

                np1.run(0.1);
                np2.run(0.1);
            }
        } catch (Exception e){
            e.printStackTrace();
        } finally {
            np1.shutdown();
            np2.shutdown();
        }

        Assertions.assertTrue(checkNp1IdentOk);
        Assertions.assertTrue(checkNp2IdentOk);


    }

    @Test
    public void identitySetKeyTest(){
        NeuropilNode np1 = new NeuropilNode(4001, false, "logs/smoke_test_identity_nl1.log");

        try {
            //generate key
            KeyPairGenerator gen = KeyPairGenerator.getInstance("ed25519");
            KeyPair keyPair = gen.generateKeyPair();
            byte[] secret = keyPair.getPrivate().getEncoded(); //In python binding they concat private and public key to send. I don`t know why.

            NpToken identity = np1.newIdentity(secret);
            np1.useIdentity(identity);
            TestHelper.disableAAA(np1);
            np1.run(0);

            int timeout = 60;
            Double t1 = System.currentTimeMillis()/1000.0;
            Double elapsed = 0.;

            try{
                while(elapsed < timeout){
                    elapsed = (System.currentTimeMillis()/1000.0) - t1;

                    Assertions.assertTrue(np1.getStatus() == NpStatus.NP_RUNNING.intValue());

                    np1.run(0.1);
                }
            } catch (Exception e){
                e.printStackTrace();
            } finally {
                np1.shutdown();
            }


        } catch (Exception e){
            e.printStackTrace();
        }
    }


    public static boolean authzAllowAllCheckIdent1(NeuropilNode node, NpToken token) {
        checkNp1IdentOk = checkIdent(np1Ident, node, token);
        return checkNp1IdentOk;
    }

    public static boolean authzAllowAllCheckIdent2(NeuropilNode node, NpToken token) {
        checkNp2IdentOk = checkIdent(np2Ident, node, token);
        return checkNp2IdentOk;
    }

    public static boolean checkIdent(NpToken npToken, NeuropilNode node, NpToken incommingToken){
        int incommingFp = incommingToken.getFingerprint(node);
        int fp = npToken.getFingerprint(node);
        return incommingFp == fp;
    }

    public static byte[] concat(byte[]... arrays) {
        int length = 0;
        for (byte[] array : arrays) {
            length += array.length;
        }
        byte[] result = new byte[length];
        int pos = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, pos, array.length);
            pos += array.length;
        }
        return result;
    }

}