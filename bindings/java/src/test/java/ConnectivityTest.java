import enums.NpStatus;
import helper.TestHelper;
import models.NeuropilCluster;
import models.NeuropilNode;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;


public class ConnectivityTest {

    @Test
    public void testConnectivity() {

        NeuropilCluster npC = new NeuropilCluster(
                3, 4010, false, "logs/smoke_test_connectivity_cl_");
        NeuropilNode np1 = new NeuropilNode(4001, false, "logs/smoke_nl1.log");
        NeuropilNode np2 = new NeuropilNode(4002, false, "logs/smoke_nl2.log");

        TestHelper.disableAAA(npC);
        npC.run(0);
        TestHelper.disableAAA(np1);
        np1.run(0);
        TestHelper.disableAAA(np2);
        np2.run(0);

        String np1Addr = np1.getAddress();
        String np2Addr = np2.getAddress();

        np2.join(np1Addr);
        npC.join(np2Addr);

        int timeout = 60;

        Double t1 = System.currentTimeMillis()/1000.0;
        Double elapsed = 0.;
        Boolean np1Joined = false;
        Boolean np2Joined = false;

        try{
            while(elapsed < timeout){
                elapsed = (System.currentTimeMillis()/1000.0) - t1;

                Double mod = elapsed / 2;
                if(mod == 0){
                    Assertions.assertTrue(np1.getStatus() == NpStatus.NP_RUNNING.intValue());
                    Assertions.assertTrue(np2.getStatus() == NpStatus.NP_RUNNING.intValue());

                    for (NeuropilNode node : npC.nodes){
                        Assertions.assertTrue(node.getStatus() == NpStatus.NP_RUNNING.intValue());
                    }
                }
                np1Joined = np1.hasJoined();
                np2Joined = np2.hasJoined();

                if (np1Joined && np2Joined)
                    break;

                np1.run(0.1);
            }
        } catch (Exception e){
            e.printStackTrace();
        } finally {
            np1.shutdown();
            np2.shutdown();
            npC.shutdown();
        }

        Assertions.assertTrue(np1Joined);
        Assertions.assertTrue(np2Joined);

    }

}