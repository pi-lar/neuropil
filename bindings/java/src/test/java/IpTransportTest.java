import models.NeuropilNode;
import models.NpToken;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import utils.NeuropilUtils;

import java.util.Calendar;
import java.util.List;


public class IpTransportTest {


    public void run_node(int port, String proto,String joinTo)  {

       // udp4_connections = Value(c_int, 0);
       // udp6_connections = Value(c_int, 0);
       // tcp4_connections = Value(c_int, 0);
       // tcp6_connections = Value(c_int, 0);
      //  pas4_connections = Value(c_int, 0);
       // pas6_connections = Value(c_int, 0);

/*

    public void run_node(int port, String proto,String joinTo)  {

        NeuropilNode np1 = new NeuropilNode(port,  proto,"logs/smoke_nl1.log",true);
        np1.setAuthenticateCb(true);
        if (joinTo !=null){
            NeuropilUtils.join(np1.getContext(), joinTo);
        }
        NeuropilUtils.run(np1.getContext(),0);

        int timeout = 180;

        Long t1 = Calendar.getInstance().getTimeInMillis();
        float elapsed = 0;
        try{
            int i = 0;
            while(elapsed < timeout){
                elapsed = Calendar.getInstance().getTimeInMillis() - t1;
                if(elapsed  > timeout){
                    break;
                }
                NeuropilUtils.run(np1.getContext(),0.0);
            }
        } catch (Exception e){
            e.printStackTrace();
        } finally {
            np1.shutdown();
        }
    }

    @Test
    public void ipTransportTest(){

        List<Object> processes;

*/
    }


}