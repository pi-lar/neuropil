
import enums.NpReturn;
import helper.TestHelper;
import models.NeuropilCluster;
import models.NeuropilNode;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import utils.NeuropilUtils;

import java.util.Calendar;


public class MsgDeliveryTest {

    int portIndex = 1;

    @Test
    public void testMsgXDelivery() throws InterruptedException {

        int msgSize = 100;
        int clusterSize = 0;
        String protocolCluster = "udp4";
        String protocolSender = "udp4";
        String protocolReceiver = "udp4";
        int tokenTimeout = 140;
        int sendTimeout = 240;
        boolean setIdentitySender = false;
        boolean setIdentityReceiver = false;
        boolean setIdentityCluster = false;

        boolean msgDeliverySize = false;

        boolean msgDeliverySucc = false;

        NeuropilCluster npC = null;

        NeuropilNode np1 = new NeuropilNode(4002+portIndex, false, "logs/smoke_nl1.log");
        portIndex+=1;
        NeuropilNode np2 = new NeuropilNode(4003+portIndex, false, "logs/smokeS_nl2.log");
        portIndex+=1;

        if(clusterSize > 0){
            npC = new NeuropilCluster(clusterSize,4001+portIndex,false,"logs/smoke_nl0_cloud");
            if(setIdentityCluster){
                npC.nodes.stream().map(npc -> npc.useIdentity(np1.newIdentity()));
            }
        }
        portIndex+=clusterSize;

        if(setIdentitySender){
            np1.useIdentity(np1.newIdentity());
        }
        if(setIdentityReceiver){
            np2.useIdentity(np2.newIdentity());
        }

        byte[] subject = "NP.TEXT.msg_delivery".getBytes();
        var mxp = NeuropilUtils.getMxProperties(np1.getContext(),subject);
        //enough parameter
        /*mxp.setNpMxAckmode(neuropil.NP_MX_ACK_DESTINATION);
        mxp.setNpMxRole(neuropil.NP_MX_PROVIDER);*/
        mxp.setMaxRetry(10);
        /*
        mxp.apply()
        mxp.set_attr_policy_bin("test_attr", b'test')
         */

        var mxp1 = NeuropilUtils.getMxProperties(np2.getContext(),subject);
        /*mxp1.setNpMxAckmode(neuropil.NP_MX_ACK_DESTINATION);
        mxp1.setNpMxRole(neuropil.NP_MX_PROVIDER);*/
        /*
        mxp1.apply()
        receiver1.set_attr_bin("test_attr", b"test", inheritance=neuropil.NP_ATTR_INTENT)
        receiver1.set_receive_cb(subject, self.cb_payload_1_received)*/


        if(npC != null){
            //npC.nodes.disableAAA()
        }
        //sender1.disableAAA();
        np1.run(0);
        //np1.disableAAA();
        np2.run(0);
        //np2.disableAAA();


        String np1Addr = np1.getAddress();
        String np2Addr = np2.getAddress();

        if(npC != null){
            np1.join(np1Addr);
        }
        np2.join(np1Addr);


        int timeout = tokenTimeout;

        Long t1 = Calendar.getInstance().getTimeInMillis();
        float elapsed = 0;
        boolean send = false;
        float lastElapsed = 0;
        try{
            int i = 0;
            while(elapsed < timeout && !msgDeliverySize){
                elapsed = Calendar.getInstance().getTimeInMillis() - t1;



                if( true /*!send && np1.hasReceiverFor(subject)*/){
                    if(true  /*np1.send(subject,data) != NpReturn.NP_OK.intValue()*/){
                        System.out.println("ERROR sending Data");
                    }else {
                        timeout = sendTimeout;
                        send = true;
                    }
                }


                if(msgDeliverySucc){
                    break;
                }

                np1.run(0.01);

            }
        } catch (Exception e){
            e.printStackTrace();
        } finally {
            np1.shutdown();
            np2.shutdown();
            if(npC!=null){
                npC.shutdown();
            }


        }

        Assertions.assertTrue(send);
        Assertions.assertTrue(msgDeliverySucc);

    }




    @Test
    public void testPolicy2Sender2Receiver2ChannelCloud() throws InterruptedException {

        boolean abortTest = false;
        String cause = "";
        boolean payload1Received = false;
        boolean payload2Received = false;

        //fn = inspect.stack
        NeuropilCluster cloud = new NeuropilCluster(1,4050,false,"logs/smoke_nl0_cloud");
        NeuropilNode sender1 = new NeuropilNode(
                4001, false, "logs/smoke_nl1_sender1.log");
        NeuropilNode sender2 = new NeuropilNode(
                4002, false, "logs/smokeS_nl2_sender2.log");
        NeuropilNode receiver1 = new NeuropilNode(
                4003, false, "logs/smokeS_nl2_receiver1.log");
        NeuropilNode receiver2 = new NeuropilNode(
                4004, false, "logs/smokeS_nl2_receiver2.log");


        byte[] subject = "NP.TEXT.msg_delivery".getBytes();
        var mxp = NeuropilUtils.getMxProperties(sender1.getContext(),subject);
        //enough parameter
        /*mxp.setNpMxAckmode(neuropil.NP_MX_ACK_DESTINATION);
        mxp.setNpMxRole(neuropil.NP_MX_PROVIDER);*/
        mxp.setMaxRetry(10);
        /*
        mxp.apply()
        mxp.set_attr_policy_bin("test_attr", b'test')
         */

        var mxp1 = NeuropilUtils.getMxProperties(sender2.getContext(),subject);
        /*mxp1.setNpMxAckmode(neuropil.NP_MX_ACK_DESTINATION);
        mxp1.setNpMxRole(neuropil.NP_MX_PROVIDER);*/
        mxp1.setMaxRetry(10);
        /*
        mxp1.apply()
        sender2.set_attr_bin("test_attr", b"test", inheritance=neuropil.NP_ATTR_INTENT)
        sender2.set_receive_cb(subject, self.cb_payload_1_received)
         */

        var mxp2 = NeuropilUtils.getMxProperties(receiver1.getContext(),subject);
        /*mxp2.setNpMxAckmode(neuropil.NP_MX_ACK_DESTINATION);
        mxp2.setNpMxRole(neuropil.NP_MX_PROVIDER);*/
        /*
        mxp2.apply()
        receiver2.set_attr_bin("test_attr", b"test", inheritance=neuropil.NP_ATTR_INTENT)
        receiver2.set_receive_cb(subject, self.cb_payload_1_received)
         */

        var mxp3 = NeuropilUtils.getMxProperties(receiver2.getContext(),subject);
        /*mxp2.setNpMxAckmode(neuropil.NP_MX_ACK_DESTINATION);
        mxp2.setNpMxRole(neuropil.NP_MX_PROVIDER);*/
        /*
        mxp2.apply()
        receiver2.set_attr_bin("test_attr", b"test", inheritance=neuropil.NP_ATTR_INTENT)
        receiver2.set_receive_cb(subject, self.cb_payload_1_received)
         */

        //cloud.nodes.disableAAA()
        //sender1.disableAAA();
        sender1.run(0);
        //receiver1.disableAAA();
        receiver1.run(0);
        //receiver2.disableAAA();
        receiver2.run(0);
        //sender2.disableAAA();
        sender2.run(0);


        cloud.nodes.forEach( adresses -> {
            adresses.getAddress();
        });

        String senderAddr = sender1.getAddress();

        receiver2.join(senderAddr);
        sender2.join(senderAddr);

        int timeout = 290;

        Long t1 = Calendar.getInstance().getTimeInMillis();
        float elapsed = 0;
        float lastElapsed = 0;
        try{
            int i = 0;
            while(elapsed < timeout){
                elapsed = Calendar.getInstance().getTimeInMillis() - t1;


                if(elapsed - lastElapsed > 0){
                    lastElapsed = elapsed;
                    /*if(sender1.send(subject,"test_payload_1") !=  NpReturn.NP_OK.intValue()){
                        System.out.println("ERROR sending data");
                    }*/
                    /*if(sender2.send(subject,"test_payload_1") !=  NpReturn.NP_OK.intValue()){
                        System.out.println("ERROR sending data");
                    }*/
                }

                sender1.run(0.01);

            }
        } catch (Exception e){
            e.printStackTrace();
        } finally {
            sender1.shutdown();
            receiver1.shutdown();
            receiver2.shutdown();
            sender2.shutdown();
        }

        Assertions.assertFalse(abortTest,cause);
        Assertions.assertTrue(payload1Received);
        Assertions.assertTrue(payload2Received);

    }




}