import models.NeuropilCluster;
import models.NeuropilNode;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import utils.NeuropilUtils;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Calendar;


public class AttributesTest {

    private boolean[] ATTRIBUTE_FOUND ={ false,false,false,false};

    @Test
    public void testConnectivity() throws InterruptedException {
        /*
        NeuropilNode np1 = new NeuropilNode(
                   4001, false, "logs/smoke_nl1.log");
        NeuropilNode np2 = new NeuropilNode(
                   4002, false, "logs/smokeS_nl2.log");

        var ident = NeuropilUtils.newIdentity(np1.getContext());

        //Method npToken
        //iden.setAttrBin("1TEST")

        NeuropilUtils.useIdentity(np1.getContext(),ident);

        //iden.setAttrBin("2TEST")
        //iden.setAttrBin("3TEST")
        //iden.setAttrBin("4TEST")



        //TestHelper.disableAAA(np1).run(0);

        NeuropilUtils.run(np1.getContext(),0);
        NeuropilUtils.run(np2.getContext(),0);

        String np1Addr = NeuropilUtils.getAddress(np1.getContext());
        String np2Addr = NeuropilUtils.getAddress(np2.getContext());

        NeuropilUtils.join(np2.getContext(), np2Addr);
        //npC.join(np2Addr);

        int timeout = 120;

        Long t1 = Calendar.getInstance().getTimeInMillis();
        float elapsed = 0;
        try{
            int i = 0;
            while(elapsed < timeout){
                elapsed = Calendar.getInstance().getTimeInMillis() - t1;

                NeuropilUtils.run(np1.getContext(),0.01);
                NeuropilUtils.run(np2.getContext(),0.01);

                if (ATTRIBUTE_FOUND[i])
                    break;
                i++;
            }
        } catch (Exception e){
            e.printStackTrace();
        } finally {
            np1.shutdown();
            np2.shutdown();
        }

        for(int i = 1; i < 5 ; i++){
            Assertions.assertTrue(ATTRIBUTE_FOUND[i-1],"attribute"+i+"not found");
        }
        */
    }

}