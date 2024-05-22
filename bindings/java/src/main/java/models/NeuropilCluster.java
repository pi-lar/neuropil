package models;

import common.LoadLibrary;
import interfaces.Neuropil;
import utils.NeuropilUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;

public class NeuropilCluster {
    
    public Integer count;
    public Integer portRange;
    public String host;
    public String proto;
    public boolean autoRun;
    public String logFilePrefix;

    public List<NeuropilNode> nodes;

    public NeuropilCluster(Integer count, Integer portRange, String host, String proto, boolean autoRun1, String logFilePrefix, List<NeuropilNode> nodes) {
        this.count = count;
        this.portRange = portRange;
        this.host = host;
        this.proto = proto;
        this.autoRun = autoRun1;
        this.logFilePrefix = logFilePrefix;
        this.nodes = nodes;
    }

    public NeuropilCluster(Integer count, Integer portRange, boolean autoRun, String logFilePrefix){

        this.nodes = new ArrayList<>();
        this.proto = "udp4";
        this.host = "localhost";

        NeuropilNode node;
        try{
            if( count <= 0){
                throw new Exception("The `count` of a cluster needs to be greater than 0");
            }

            int[] portRangeArray = IntStream.range(portRange, portRange+count).toArray();

            for(int c : IntStream.range(0, count).toArray()){
                int port = portRangeArray[c];
                String logFile = logFilePrefix+this.host+"_"+port+".log";
                node = new NeuropilNode(port, this.host, this.proto, true, logFile); //aqui teria um ponteiro para **setings
                this.nodes.add(node);

            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public void run(double duration){
        if(!this.nodes.isEmpty()) {
            this.nodes.forEach(node -> {
                node.run(duration);
            });
        }
    }

    public void join(String connectString){
        if(!this.nodes.isEmpty()){
            this.nodes.forEach(node -> node.join(connectString));
        }
    }

    public void shutdown(){
        if(!this.nodes.isEmpty()){
            Neuropil neuropil = LoadLibrary.getInstance().neuropil;
            this.nodes.forEach(node -> {
                node.setDestroyed(true);
                neuropil.np_destroy(node.getContext(), true);
            });
        }
    }


}
