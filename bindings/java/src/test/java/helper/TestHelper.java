package helper;

import models.NeuropilCluster;
import models.NeuropilNode;
import models.NpToken;

public class TestHelper {

    public static void disableAAA(NeuropilNode node) {
        try {
            node.setAuthenticateCb(TestHelper.class.getDeclaredMethod("authnAllowAll",
                    NeuropilNode.class, NpToken.class));
            node.setAuthorizeCb(TestHelper.class.getDeclaredMethod("authzAllowAll",
                    NeuropilNode.class, NpToken.class));
            node.setAccountingCb(TestHelper.class.getDeclaredMethod("accAllowAll",
                    NeuropilNode.class, NpToken.class));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public static void disableAAA(NeuropilCluster cluster){
        try {
            if(!cluster.nodes.isEmpty()) {
                cluster.nodes.forEach(node -> {
                    disableAAA(node);
                });
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static boolean authnAllowAll(NeuropilNode node, NpToken token) {
        return true;
    }

    public static boolean authzAllowAll(NeuropilNode node, NpToken token) {
        return true;
    }

    public static boolean accAllowAll(NeuropilNode node, NpToken token) {
        return true;
    }
}
