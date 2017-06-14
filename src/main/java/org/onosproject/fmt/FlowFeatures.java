package org.onosproject.fmt;

/**
 * Created by root on 16. 11. 14.
 */
public interface FlowFeatures {
    public enum Model {

        RBF("RBFNetwork.model"),
        MLP("MultilayerPerceptron.model"),
        NAB("BayesNet.model");

        private String model;

        Model(String model) {
            this.model = model;
        }

        public String getModel() {
            return model;
        }
    }

    public enum Attributes {
        DURATION("duration"),
        PROTOCOL_TYPE("protocol_type"),
        SRC_BYTES("src_bytes"),
        DST_BYTES("dst_bytes"),
        LAND("land"),
        COUNT("count"),
        SRV_COUNT("srv_count"),
        SAME_SRV_RATE("same_srv_rate"),
        DIFF_SRV_RATE("diff_srv_rate"),
        SRV_DIFF_HOST_RATE("srv_diff_host_rate"),
        DST_HOST_COUNT("dst_host_count"),
        DST_HOST_SRV_COUNT("dst_host_srv_count"),
        DST_HOST_SAME_SRV_RATE("dst_host_same_srv_rate"),
        DST_HOST_DIFF_SRV_RATE("dst_host_diff_srv_rate"),
        DST_HOST_SAME_SRV_PORT_RATE("dst_host_same_src_port_rate"),
        DST_HOST_SRV_DIFF_HOST_RATE("dst_host_srv_diff_host_rate"),
        ATTACK("attack");

        private String attribute;

        Attributes(String attribute) {
            this.attribute = attribute;
        }

        public String getAttribute() {
            return attribute;
        }
    }
}
