package org.onosproject.fmt;

import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.TpPort;
import org.onosproject.net.flow.FlowEntry;

import java.util.Objects;

/**
 * Created by root on 16. 11. 10.
 */
public class TrafficFeature {
    private Ip4Prefix src = null;
    private Ip4Prefix dst = null;
    private String protocol = null;
    private TpPort port = null;
    private FlowEntry flowrule = null;

    public TrafficFeature() {}
    public TrafficFeature(Ip4Prefix src, Ip4Prefix dst, String protocol, TpPort port, FlowEntry flowrule) {
        this.src = src;
        this.dst = dst;
        this.protocol = protocol;
        this.port = port;
        this.flowrule = flowrule;
    }

    public Ip4Prefix getSrc() {
        return src;
    }

    public void setSrc(Ip4Prefix src) {
        this.src = src;
    }

    public Ip4Prefix getDst() {
        return dst;
    }

    public void setDst(Ip4Prefix dst) {
        this.dst = dst;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public TpPort getPort() {
        return port;
    }

    public void setPort(TpPort port) {
        this.port = port;
    }

    public FlowEntry getFlowrule() {
        return flowrule;
    }

    public void setFlowrule(FlowEntry flowrule) {
        this.flowrule = flowrule;
    }

    @Override
    public boolean equals(java.lang.Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        TrafficFeature that = (TrafficFeature) obj;
        return Objects.equals(src, that.src) &&
                Objects.equals(dst, that.dst) &&
                Objects.equals(port.toInt(), that.port.toInt());
    }
    @Override
    public int hashCode() {
        return Objects.hash(src, dst);
    }
}
