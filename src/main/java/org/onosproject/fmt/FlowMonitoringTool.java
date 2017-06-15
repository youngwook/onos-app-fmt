/*
 * Copyright 2016-present Open Networking Laboratory
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.onosproject.fmt;

import org.onlab.packet.IpAddress;
import org.onosproject.net.Host;
import org.onosproject.net.host.HostService;
import org.osgi.service.component.ComponentContext;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.Service;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.TpPort;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.flow.DefaultFlowEntry;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.IPCriterion;
import org.onosproject.net.flow.criteria.IPProtocolCriterion;
import org.onosproject.net.flow.criteria.TcpPortCriterion;
import org.onosproject.net.flow.criteria.UdpPortCriterion;
import org.onosproject.net.flow.instructions.Instructions;
import org.onosproject.net.topology.TopologyGraph;
import org.onosproject.net.topology.TopologyService;
import org.onosproject.net.topology.TopologyVertex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import weka.classifiers.Classifier;
import weka.core.Instances;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
@Service(value = FlowMonitoringTool.class)
public class FlowMonitoringTool implements FlowFeatures {

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected TopologyService topologyService;

    private ApplicationId appId;

    private static final String FILE_PATH = System.getProperty("user.home") + "/";

    private static final int CURRENTTIME = 2;

    private static final int DEFAULT_TIMEOUT = 8;

    private static final int DEFAULT_PRIORITY = 10;

    private final Logger log = LoggerFactory.getLogger(getClass());

    private static List<Map<TrafficFeature, List<String>>> ins = new ArrayList<Map<TrafficFeature, List<String>>>();

    private static FlowClassify classifier = new FlowClassify();

    private static Classifier RBF;

    private static Classifier VOTE;

    private static Classifier MP;

    @Activate
    protected void activate(ComponentContext context) {

        appId = coreService.registerApplication("org.onosproject.fmt");

        RBF = classifier.getClassifier();

        MP = classifier.getClassifier(1);

        VOTE = classifier.getClassifiers();

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        log.info("Stopped");
    }

    public static Classifier getRBF() {
        return RBF;
    }

    public static Classifier getVOTE() {
        return VOTE;
    }


    public static List<Map<TrafficFeature, List<String>>> getIns() {
        List<Map<TrafficFeature, List<String>>> instances;
        synchronized (ins) {
            instances = new ArrayList<Map<TrafficFeature, List<String>>>(ins);
            cleanIns();
        }
        return instances;
    }

    public static void addIns(Map<TrafficFeature, List<String>> instance) {
        synchronized (ins) {
            ins.add(instance);
        }
    }
    public static void cleanIns() {
        synchronized (ins) {
            ins.clear();
        }
    }
    public static FlowClassify getClassifier() {
        return classifier;
    }

    public boolean putArffFile(String name) {
        List<Map<TrafficFeature, List<String>>> traffics = getIns();
        if (traffics.isEmpty()) {
            return false;
        }
        Instances ins = classifier.getInstances(traffics);
        classifier.writeArffFiles(ins, name);
        return true;
    }

    // About Firewall Rule Install

    // block abnormal flows - 2017.6.14
    public void block(int i) {
        DeviceId deviceId = getDeviceId("of:0000000000000006");
        Map<DeviceId, Set<TrafficFeature>> firewalls = getInstalledFirewall(deviceId);
        Set<TrafficFeature> installedRules = new HashSet<TrafficFeature>();

        Set<TrafficFeature> firewall = firewalls.get(deviceId);

        Map<TrafficFeature, Double> values = classifyAndResults();
        log.info("");
        for (TrafficFeature tf : values.keySet()) {
            if (values.get(tf) > 0) {
                log.info("value of results " + values.get(tf));
                if (firewall == null) {
                    flowRuleInstall(tf.getFlowrule().deviceId(), tf);
                    log.info("install rule to " + tf.getFlowrule().deviceId());
                }
                else if (!eq(firewall, tf)) {
                    flowRuleInstall(tf.getFlowrule().deviceId(), tf);
                    log.info("install rule to " + tf.getFlowrule().deviceId());
                }

            }
        }
        log.info("");
//        for (TrafficFeature tf : firewall) {
//            if (eq(installedRules, tf)) {
//                flowRuleRemove(tf.getFlowrule().deviceId(), tf);
//                log.info("remove rule from " + tf.getFlowrule().deviceId());
//            }
//        }
    }
    public boolean eq (Set<TrafficFeature> firewall, TrafficFeature tf) {
        boolean re = false;
        for (TrafficFeature f : firewall) {
            if (f.getSrc().contains(tf.getSrc())) {
                if (f.getDst().contains(tf.getDst())) {
                    if (f.getProtocol().equals(tf.getProtocol())) {
                        re = true;
                    }
                }
            }
        }
        return re;
    }

    // block abnormal flows
    public void block() {
        DeviceId deviceId = getDeviceId("of:0000000000000006");
        Map<DeviceId, Set<TrafficFeature>> firewalls = getInstalledFirewall(deviceId);
        Set<TrafficFeature> installedRules = new HashSet<TrafficFeature>();

        Set<TrafficFeature> firewall = firewalls.get(deviceId);

        Map<TrafficFeature, Double> values = classifyResults();
        log.info("");
        for (TrafficFeature tf : values.keySet()) {
            if (values.get(tf) > 0) {
                log.info("value of results " + values.get(tf));
                if (firewall == null) {
                    flowRuleInstall(tf.getFlowrule().deviceId(), tf);
                    log.info("install rule to " + tf.getFlowrule().deviceId());
                }
                else if (!eq(firewall, tf)) {
                    flowRuleInstall(tf.getFlowrule().deviceId(), tf);
                    log.info("install rule to " + tf.getFlowrule().deviceId());
                }

            }
        }
        log.info("");

    }

    // block abnormal flows by algorithms
    public void blocks() {
        Map<TrafficFeature, Double> values = classifyAndResults();
        for (TrafficFeature tf : values.keySet()) {
            if (values.get(tf) > 0) {
//                DeviceId deviceId = getLocatedDevice(tf);
//                flowRuleInstall(deviceId != null ? deviceId : tf.getFlowrule().deviceId(), tf);
                flowRuleInstall(tf.getFlowrule().deviceId(), tf);
                log.info("install rule to " + tf.getFlowrule().deviceId());
            }
        }
    }
    public DeviceId getLocatedDevice(TrafficFeature tf) {
        DeviceId deviceId = null;
        List<DeviceId> devices = getDeviceId();
        for (DeviceId did : devices) {
            for (Host host : hostService.getConnectedHosts(did)) {
                for (IpAddress ipAddress : host.ipAddresses()) {
                    if (ipAddress.equals(tf.getSrc().address())) {
                        return did;
                    }
                }
            }
        }
        return null;
    }

    // About Classify and Results

    //classify and get results using single algorithm
    public Map<TrafficFeature, Double> classifyResults(int iz) {
        List<Map<TrafficFeature, List<String>>> traffics = getIns();
        Map<TrafficFeature, Double> results = new LinkedHashMap<TrafficFeature, Double>();
        for (Map<TrafficFeature, List<String>> list : traffics) {
            Instances ins = classifier.getInstances(list);
            Set<TrafficFeature> keySet = list.keySet();
            int i = 0;
            for (TrafficFeature feature : keySet) {
                double value = classifier.classify(MP, ins.instance(i++));
                if (results.containsKey(feature)) {
                    results.put(feature, results.get(feature) + value);
                } else {

                    results.put(feature, value);
                }
            }
        }
        return results;
    }

    //classify and get results using single algorithm
    public Map<TrafficFeature, Double> classifyResults() {
        List<Map<TrafficFeature, List<String>>> traffics = getIns();
        Map<TrafficFeature, Double> results = new LinkedHashMap<TrafficFeature, Double>();
        for (Map<TrafficFeature, List<String>> list : traffics) {
            Instances ins = classifier.getInstances(list);
            Set<TrafficFeature> keySet = list.keySet();
            int i = 0;
            for (TrafficFeature feature : keySet) {
                double value = classifier.classify(RBF, ins.instance(i++));
                if (results.containsKey(feature)) {
                    results.put(feature, results.get(feature) + value);
                } else {

                    results.put(feature, value);
                }
            }
        }
        return results;
    }

    //classify and get results using muilty algorithm
    public Map<TrafficFeature, Double> classifyAndResults() {
        List<Map<TrafficFeature, List<String>>> traffics = getIns();
        Map<TrafficFeature, Double> results = new LinkedHashMap<TrafficFeature, Double>();
        for (Map<TrafficFeature, List<String>> list : traffics) {
            Instances ins = classifier.getInstances(list);
            Set<TrafficFeature> keySet = list.keySet();
            int i = 0;
            for (TrafficFeature feature : keySet) {
                double value = classifier.classify(VOTE, ins.instance(i++));
                if (results.containsKey(feature)) {
                    results.put(feature, results.get(feature) + value);
                } else {

                    results.put(feature, value);
                }
            }
        }
        return results;
    }

    //About Export Received Data Set

    // put instances which from devices, home directory on named format
    public synchronized void putTrafficfeatures(List<Map<TrafficFeature, List<String>>> features, String name) {
        File file = new File(FILE_PATH + name);
        FileWriter fw = checkFile(file);

        try {
            for (Map<TrafficFeature, List<String>> feature : features) {
                Set<TrafficFeature> keySet = feature.keySet();
                for (TrafficFeature key : keySet) {
                    List<String> values = feature.get(key);
                    for (int i = 0; i < values.size() - 1; i++) {
                        fw.write(values.get(i) + ",");
                    }
                    fw.write(values.get(values.size() - 1) + "\n");
                    fw.flush();
                }
            }
            fw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
    // put instances home directory on named format
    public synchronized void putTrafficfeatures(Map<TrafficFeature, List<String>> features, String name) {
        File file = new File(FILE_PATH + name);
        FileWriter fw = checkFile(file);

        try {
            Set<TrafficFeature> keySet = features.keySet();
            for (TrafficFeature key : keySet) {
                List<String> values = features.get(key);
                for (int i = 0; i < values.size() - 1; i++) {
                    fw.write(values.get(i) + ",");
                }
                fw.write(values.get(values.size() - 1) + "\n");
                fw.flush();
            }
            fw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
    public FileWriter checkFile(File file) {
        FileWriter fw = null;
        if (file.exists()) {
            try {
                return new FileWriter(file, true);
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            try {
                file.createNewFile();
                fw = new FileWriter(file, true);

                for (Attributes at : Attributes.values()) {
                    fw.write(at.getAttribute().equals("attack")
                                     ? at.getAttribute() + "\n" : at.getAttribute() + ",");
                }
                fw.flush();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return fw;
    }

    // About Flow Rule Generation and Install

    // install firewall rull to device
    public synchronized void flowRuleInstall(DeviceId dviceId, TrafficFeature rule) {
        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();
        TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder();
        FlowEntry.Builder flowEntry = DefaultFlowEntry.builder();

        selectorBuilder.matchEthType(Ethernet.TYPE_IPV4);
        selectorBuilder.matchIPSrc(rule.getSrc());
        selectorBuilder.matchIPDst(rule.getDst());
        byte proto = 17;
        if (rule.getProtocol().equals("tcp")) {
            proto = IPv4.PROTOCOL_TCP;
//            selectorBuilder.matchTcpDst(rule.getPort());
        }
        if (rule.getProtocol().equals("udp")) {
            proto = IPv4.PROTOCOL_UDP;
//            selectorBuilder.matchUdpDst(rule.getPort());
        }
        if (rule.getProtocol().equals("icmp")) {
            proto = IPv4.PROTOCOL_ICMP;
        }
        selectorBuilder.matchIPProtocol(proto);

        treatment.add(Instructions.createNoAction());

        flowEntry.forDevice(dviceId);
        flowEntry.withPriority(DEFAULT_PRIORITY);
        flowEntry.withSelector(selectorBuilder.build());
        flowEntry.withTreatment(treatment.build());
        flowEntry.fromApp(appId);
        flowEntry.makeTemporary(DEFAULT_TIMEOUT);
        flowRuleService.applyFlowRules(flowEntry.build());
    }

    // Remove timeout flow rules
    public synchronized void flowRuleRemove(DeviceId dviceId, TrafficFeature rule) {
        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();
        TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder();
        FlowEntry.Builder flowEntry = DefaultFlowEntry.builder();

        selectorBuilder.matchEthType(Ethernet.TYPE_IPV4);
        selectorBuilder.matchIPSrc(rule.getSrc());
        selectorBuilder.matchIPDst(rule.getDst());
        byte proto = 17;
        if (rule.getProtocol().equals("tcp")) {
            proto = IPv4.PROTOCOL_TCP;
            selectorBuilder.matchTcpDst(rule.getPort());
        }
        if (rule.getProtocol().equals("udp")) {
            proto = IPv4.PROTOCOL_UDP;
            selectorBuilder.matchUdpDst(rule.getPort());
        }
        if (rule.getProtocol().equals("icmp")) {
            proto = IPv4.PROTOCOL_ICMP;
        }
        selectorBuilder.matchIPProtocol(proto);

        treatment.add(Instructions.createNoAction());

        flowEntry.forDevice(dviceId);
        flowEntry.withPriority(DEFAULT_PRIORITY);
        flowEntry.withSelector(selectorBuilder.build());
        flowEntry.withTreatment(treatment.build());
        flowEntry.fromApp(appId);
        flowEntry.makeTemporary(DEFAULT_TIMEOUT);
        flowRuleService.removeFlowRules(flowEntry.build());
    }

    //get Instances form a devices
    public synchronized Map<TrafficFeature, List<String>> getInstances(String id) {
        DeviceId deviceId = getDeviceId(id);
        Map<DeviceId, Set<TrafficFeature>> trafficFeatures = getTrafficFeatures(deviceId);
        Set<TrafficFeature> fullConnections = getFlowFeatures(trafficFeatures);
        Set<TrafficFeature> currentConnections = getFlowFeatures(fullConnections);
        Map<Ip4Prefix, Set<TrafficFeature>> sameHostOfFC = getSameDstFeatures(fullConnections);
        Map<TpPort, Set<TrafficFeature>> sameServiceOfFC = getSameServiceFeatrues(fullConnections);
        Map<Ip4Prefix, Set<TrafficFeature>> sameHostOfCC = getSameDstFeatures(currentConnections);
        Map<TpPort, Set<TrafficFeature>> sameServiceOfCC = getSameServiceFeatrues(currentConnections);
        Map<TrafficFeature, TrafficFeature> pairedConnections = getPairedFeatures(fullConnections);
        float currentConnectionsNum = currentConnections.size();
        float fullConnectionsNum = fullConnections.size();

        Map<TrafficFeature, List<String>> instances = new LinkedHashMap<TrafficFeature, List<String>>();
        for (TrafficFeature trafficFeature: fullConnections) {
            List<String> instance = new ArrayList<String>();
            //duration
            instance.add(String.valueOf(trafficFeature.getFlowrule().life()));
            //protocol type
            instance.add(trafficFeature.getProtocol());
            //source bytes
            instance.add(String.valueOf(trafficFeature.getFlowrule().bytes()));
            //dst bytes
            instance.add(pairedConnections.containsKey(trafficFeature)
                                 ? String.valueOf(pairedConnections.get(trafficFeature).getFlowrule().bytes()) : "0");
            //land
            instance.add(trafficFeature.getSrc().contains(trafficFeature.getDst())
                                 ? "1" : "0");
            //count
            instance.add(sameHostOfCC.containsKey(trafficFeature.getDst())
                                 ? String.valueOf(sameHostOfCC.get(trafficFeature.getDst()).size()) : "0");
            //srv count
            instance.add(sameServiceOfCC.containsKey(trafficFeature.getPort())
                                 ? String.valueOf(sameServiceOfCC.get(trafficFeature.getPort()).size()) : "0");
            // same service rate = % of connections to the same service to the same
            // host as the current connection int the past two seconds
            if (!sameServiceOfCC.containsKey(trafficFeature.getPort())) {
                instance.add("0");
            } else {
                String value = currentConnectionsNum < 0 ? "0" : String.valueOf(
                        findSameServiceSameHost(sameServiceOfCC.get(
                                trafficFeature.getPort()), trafficFeature.getDst()) / currentConnectionsNum * 100);
                instance.add(value);
            }
            //diff srv rate = % of connections to different services
            // to the same host as the current connection in the past two seconds
            if (!sameHostOfCC.containsKey(trafficFeature.getDst())) {
                instance.add("0");
            } else {
                String value = currentConnectionsNum < 0 ? "0" : String.valueOf(
                        findDiffServiceSameHost(sameHostOfCC.get(
                                trafficFeature.getDst()), trafficFeature.getPort()) / currentConnectionsNum * 100);
                instance.add(value);
            }
            //srv diff host rate = % of connections to different hosts
            // to the same service as the current connection in the past two seconds
            if (!sameServiceOfCC.containsKey(trafficFeature.getPort())) {
                instance.add("0");
            } else {
                String value = currentConnectionsNum < 0 ? "0" : String.valueOf(
                        findDiffHostSameService(sameServiceOfCC.get(
                                trafficFeature.getPort()), trafficFeature.getDst()) / currentConnectionsNum * 100);
                instance.add(value);
            }
            // dst host count = ount of connections having the same destination host
            instance.add(sameHostOfFC.containsKey(trafficFeature.getDst())
                                 ? String.valueOf(sameHostOfFC.get(trafficFeature.getDst()).size()) : "0");
            //dst host srv count = count of connections having the same destination host and using the same service
            instance.add(sameServiceOfFC.containsKey(trafficFeature.getPort())
                                 ? String.valueOf(findSameServiceSameHost(
                    sameServiceOfFC.get(trafficFeature.getPort()), trafficFeature.getDst())) : "0");
            //dst host same srv rate = % of connections having the same destination host and using the same service
            if (!sameServiceOfFC.containsKey(trafficFeature.getPort())) {
                instance.add("0");
            } else {
                String value = fullConnectionsNum < 0 ? "0" : String.valueOf(
                        findSameServiceSameHost(sameServiceOfFC.get(trafficFeature.getPort()),
                                                trafficFeature.getDst()) / fullConnectionsNum * 100);
                instance.add(value);
            }
            //dst host diff srv rate = % of different services on the current host
            if (!sameHostOfFC.containsKey(trafficFeature.getDst())) {
                instance.add("0");
            } else {
                String value = fullConnectionsNum < 0 ? "0" : String.valueOf(
                        findDiffServiceSameHost(sameHostOfFC.get(trafficFeature.getDst()),
                                                trafficFeature.getPort()) / fullConnectionsNum * 100);
                instance.add(value);
            }
            //dst host same src port rate = % of connections to the current host having the same src port
            if (!sameHostOfFC.containsKey(trafficFeature.getDst())) {
                instance.add("0");
            } else {
                String value = fullConnectionsNum < 0 ? "0" : String.valueOf(
                        findSameHostSameService(sameHostOfFC.get(trafficFeature.getDst()),
                                                trafficFeature.getPort()) / fullConnectionsNum * 100);
                instance.add(value);
            }
            //dst host srv diff host rate = % of connections to the same service coming from different host
            if (!sameServiceOfFC.containsKey(trafficFeature.getPort())) {
                instance.add("0");
            } else {
                String value = fullConnectionsNum < 0 ? "0" : String.valueOf(
                        findDiffHostSameService(sameServiceOfFC.get(trafficFeature.getPort()),
                                                trafficFeature.getDst()) / fullConnectionsNum * 100);
                instance.add(value);
            }
            instances.put(trafficFeature, instance);
        }
        return instances;

    }
    //get Instances form exists devices
    public synchronized Map<TrafficFeature, List<String>> getInstances() {
        Map<DeviceId, Set<TrafficFeature>> trafficFeatures = getTrafficFeatures();
        Set<TrafficFeature> fullConnections = getFlowFeatures(trafficFeatures);
        Set<TrafficFeature> currentConnections = getFlowFeatures(fullConnections);
        Map<Ip4Prefix, Set<TrafficFeature>> sameHostOfFC = getSameDstFeatures(fullConnections);
        Map<TpPort, Set<TrafficFeature>> sameServiceOfFC = getSameServiceFeatrues(fullConnections);
        Map<Ip4Prefix, Set<TrafficFeature>> sameHostOfCC = getSameDstFeatures(currentConnections);
        Map<TpPort, Set<TrafficFeature>> sameServiceOfCC = getSameServiceFeatrues(currentConnections);
        Map<TrafficFeature, TrafficFeature> pairedConnections = getPairedFeatures(fullConnections);
        float currentConnectionsNum = currentConnections.size();
        float fullConnectionsNum = fullConnections.size();

        Map<TrafficFeature, List<String>> instances = new LinkedHashMap<TrafficFeature, List<String>>();
        for (TrafficFeature trafficFeature: fullConnections) {
            List<String> instance = new ArrayList<String>();
            //duration
            instance.add(String.valueOf(trafficFeature.getFlowrule().life()));
            //protocol type
            instance.add(trafficFeature.getProtocol());
            //source bytes
            instance.add(String.valueOf(trafficFeature.getFlowrule().bytes()));
            //dst bytes
            instance.add(pairedConnections.containsKey(trafficFeature)
                                 ? String.valueOf(pairedConnections.get(trafficFeature).getFlowrule().bytes()) : "0");
            //land
            instance.add(trafficFeature.getSrc().contains(trafficFeature.getDst())
                                 ? "1" : "0");
            //count
            instance.add(sameHostOfCC.containsKey(trafficFeature.getDst())
                                 ? String.valueOf(sameHostOfCC.get(trafficFeature.getDst()).size()) : "0");
            //srv count
            instance.add(sameServiceOfCC.containsKey(trafficFeature.getPort())
                                 ? String.valueOf(sameServiceOfCC.get(trafficFeature.getPort()).size()) : "0");
            // same service rate = % of connections to the same service to the same
            // host as the current connection int the past two seconds
            if (!sameServiceOfCC.containsKey(trafficFeature.getPort())) {
                instance.add("0");
            } else {
                String value = currentConnectionsNum < 0 ? "0" : String.valueOf(
                        findSameServiceSameHost(sameServiceOfCC.get(
                                trafficFeature.getPort()), trafficFeature.getDst()) / currentConnectionsNum * 100);
                instance.add(value);
            }
            //diff srv rate = % of connections to different services
            // to the same host as the current connection in the past two seconds
            if (!sameHostOfCC.containsKey(trafficFeature.getDst())) {
                instance.add("0");
            } else {
                String value = currentConnectionsNum < 0 ? "0" : String.valueOf(
                        findDiffServiceSameHost(sameHostOfCC.get(
                                trafficFeature.getDst()), trafficFeature.getPort()) / currentConnectionsNum * 100);
                instance.add(value);
            }
            //srv diff host rate = % of connections to different hosts
            // to the same service as the current connection in the past two seconds
            if (!sameServiceOfCC.containsKey(trafficFeature.getPort())) {
                instance.add("0");
            } else {
                String value = currentConnectionsNum < 0 ? "0" : String.valueOf(
                        findDiffHostSameService(sameServiceOfCC.get(
                                trafficFeature.getPort()), trafficFeature.getDst()) / currentConnectionsNum * 100);
                instance.add(value);
            }
            // dst host count = ount of connections having the same destination host
            instance.add(sameHostOfFC.containsKey(trafficFeature.getDst())
                                 ? String.valueOf(sameHostOfFC.get(trafficFeature.getDst()).size()) : "0");
            //dst host srv count = count of connections having the same destination host and using the same service
            instance.add(sameServiceOfFC.containsKey(trafficFeature.getPort())
                                 ? String.valueOf(findSameServiceSameHost(
                    sameServiceOfFC.get(trafficFeature.getPort()), trafficFeature.getDst())) : "0");
            //dst host same srv rate = % of connections having the same destination host and using the same service
            if (!sameServiceOfFC.containsKey(trafficFeature.getPort())) {
                instance.add("0");
            } else {
                String value = fullConnectionsNum < 0 ? "0" : String.valueOf(
                        findSameServiceSameHost(sameServiceOfFC.get(trafficFeature.getPort()),
                                                trafficFeature.getDst()) / fullConnectionsNum * 100);
                instance.add(value);
            }
            //dst host diff srv rate = % of different services on the current host
            if (!sameHostOfFC.containsKey(trafficFeature.getDst())) {
                instance.add("0");
            } else {
                String value = fullConnectionsNum < 0 ? "0" : String.valueOf(
                        findDiffServiceSameHost(sameHostOfFC.get(trafficFeature.getDst()),
                                                trafficFeature.getPort()) / fullConnectionsNum * 100);
                instance.add(value);
            }
            //dst host same src port rate = % of connections to the current host having the same src port
            if (!sameHostOfFC.containsKey(trafficFeature.getDst())) {
                instance.add("0");
            } else {
                String value = fullConnectionsNum < 0 ? "0" : String.valueOf(
                        findSameHostSameService(sameHostOfFC.get(trafficFeature.getDst()),
                                                trafficFeature.getPort()) / fullConnectionsNum * 100);
                instance.add(value);
            }
            //dst host srv diff host rate = % of connections to the same service coming from different host
            if (!sameServiceOfFC.containsKey(trafficFeature.getPort())) {
                instance.add("0");
            } else {
                String value = fullConnectionsNum < 0 ? "0" : String.valueOf(
                        findDiffHostSameService(sameServiceOfFC.get(trafficFeature.getPort()),
                                                trafficFeature.getDst()) / fullConnectionsNum * 100);
                instance.add(value);
            }
            instances.put(trafficFeature, instance);
        }
        return instances;

    }

    public float findDiffHostSameService(Set<TrafficFeature> service, Ip4Prefix host) {
        float num = 0;
        for (TrafficFeature src : service) {
            if (!src.getDst().contains(host)) {
                num++;
            }
        }
        return num++;
    }
    public float findDiffServiceSameHost(Set<TrafficFeature> host, TpPort service) {
        float num = 0;
        for (TrafficFeature src : host) {
            if (src.getPort().toInt() != service.toInt()) {
                num++;
            }
        }
        return num;
    }
    public float findSameServiceSameHost(Set<TrafficFeature> service, Ip4Prefix host) {
        float num = 0;
        for (TrafficFeature src : service) {
            if (src.getDst().contains(host)) {
                num++;
            }
        }
        return num;
    }
    public float findSameHostSameService(Set<TrafficFeature> host, TpPort service) {
        float num = 0;
        for (TrafficFeature src : host) {
            if (src.getPort().equals(service)) {
                num++;
            }
        }
        return num;
    }
    // get paired TrafficFeatures
    public Map<TrafficFeature, TrafficFeature> getPairedFeatures(Set<TrafficFeature> trafficFeatures) {
        Map<TrafficFeature, TrafficFeature> pairedFeatures = new HashMap<TrafficFeature, TrafficFeature>();
        for (TrafficFeature src: trafficFeatures) {
            for (TrafficFeature dst: trafficFeatures) {
                if (compareFeature(src, dst)) {
                    pairedFeatures.put(src, dst);
                    break;
                }
            }
        }
        return pairedFeatures;
    }
    //find paired TrafficFeatures
    public boolean compareFeature(TrafficFeature src, TrafficFeature dst) {
        if (src.getSrc().contains(dst.getDst())) {
            if (src.getDst().contains(dst.getSrc())) {
                if (src.getProtocol().equals(dst.getProtocol())) {
                    return true;
                }
            }
        }
        return false;
    }
    //get same dst host traffic from Set of TrafficFeatures
    public Map<Ip4Prefix, Set<TrafficFeature>> getSameDstFeatures(Set<TrafficFeature> trafficFeatures) {
        Map<Ip4Prefix, Set<TrafficFeature>> sameDstFeatures = new HashMap<Ip4Prefix, Set<TrafficFeature>>();
        for (TrafficFeature trafficFeature: trafficFeatures) {
            if (compareIP(sameDstFeatures, trafficFeature)) {
                sameDstFeatures.get(trafficFeature.getDst()).add(trafficFeature);
            } else {
                sameDstFeatures.put(trafficFeature.getDst(), new HashSet<TrafficFeature>());
                sameDstFeatures.get(trafficFeature.getDst()).add(trafficFeature);
            }
        }
        return sameDstFeatures;
    }
    //find same dst ip connections
    public boolean compareIP(Map<Ip4Prefix, Set<TrafficFeature>> sameDstFeatures, TrafficFeature trafficFeature) {
        if (sameDstFeatures.isEmpty()) {
            return false;
        }
        Set<Ip4Prefix> keySet = sameDstFeatures.keySet();
        for (Ip4Prefix ip: keySet) {
            if (ip.contains(trafficFeature.getDst())) {
                return true;
            }
        }
        return false;
    }

    //get same dst port traffic from Set TrafficFeatures
    public Map<TpPort, Set<TrafficFeature>> getSameServiceFeatrues(Set<TrafficFeature> trafficFeatures) {
        Map<TpPort, Set<TrafficFeature>> sameServiceFeatures = new HashMap<TpPort, Set<TrafficFeature>>();
        for (TrafficFeature trafficFeature: trafficFeatures) {
            if (comparePort(sameServiceFeatures, trafficFeature)) {
                sameServiceFeatures.get(trafficFeature.getPort()).add(trafficFeature);
            } else {
                sameServiceFeatures.put(trafficFeature.getPort(), new HashSet<TrafficFeature>());
                sameServiceFeatures.get(trafficFeature.getPort()).add(trafficFeature);
            }
        }
        return sameServiceFeatures;
    }

    //find same port connections
    public boolean comparePort(Map<TpPort, Set<TrafficFeature>> sameServiceFeatures, TrafficFeature trafficFeature) {
        if (sameServiceFeatures.isEmpty()) {
            return false;
        }
        Set<TpPort> keySet = sameServiceFeatures.keySet();
        for (TpPort port: keySet) {
            if (port.equals(trafficFeature.getPort())) {
                return true;
            }
        }
        return false;
    }

    // get flows in full connections fraom TrafficFeatures
    public Set<TrafficFeature> getFlowFeatures(Map<DeviceId, Set<TrafficFeature>> trafficFeatures) {

        Set<TrafficFeature>  flowFtures = new HashSet<TrafficFeature>();
        Set<DeviceId> deviceIds = trafficFeatures.keySet();
        for (DeviceId deviceId: deviceIds) {
            for (TrafficFeature tf: trafficFeatures.get(deviceId)) {
                if (!flowFtures.contains(tf)) {
                    flowFtures.add(tf);
                }
            }

        }
        return flowFtures;

    }

    // get flows in current connection from full connections
    public Set<TrafficFeature> getFlowFeatures(Set<TrafficFeature> trafficFeatures) {

        Set<TrafficFeature>  flowFtures = new HashSet<TrafficFeature>();
        for (TrafficFeature trafficFeature: trafficFeatures) {
            if (trafficFeature.getFlowrule().life() <= CURRENTTIME) {
                flowFtures.add(trafficFeature);
            }
        }
        return flowFtures;

    }

    // Maping Device with Flow Entry

    // Get Flow Entrys for installed firewall -2017.6.14
    public Map<DeviceId, Set<TrafficFeature>> getInstalledFirewall(DeviceId id) {
        Map<DeviceId, Set<FlowEntry>> flowentrys = getFirewalledFlowEntrys(id);
        Map<DeviceId, Set<TrafficFeature>> trafficTeatures = new HashMap<DeviceId, Set<TrafficFeature>>();
        Set<DeviceId> deviceIds = flowentrys.keySet();
        for (DeviceId deviceId: deviceIds) {
            Set<TrafficFeature> trafficFeature = new HashSet<TrafficFeature>();
            for (FlowEntry flowEntry: flowentrys.get(deviceId)) {
                trafficFeature.add(firewallEntryToTrafficFeatue(flowEntry));
            }
            trafficTeatures.put(deviceId, trafficFeature);
        }
        return trafficTeatures;
    }

    // get TrafficFeatures form received flowEntrys by a device
    public Map<DeviceId, Set<TrafficFeature>> getTrafficFeatures(DeviceId id) {
        Map<DeviceId, Set<FlowEntry>> flowentrys = getFlowEntrys(id);
        Map<DeviceId, Set<TrafficFeature>> trafficTeatures = new HashMap<DeviceId, Set<TrafficFeature>>();
        Set<DeviceId> deviceIds = flowentrys.keySet();
        for (DeviceId deviceId: deviceIds) {
            Set<TrafficFeature> trafficFeature = new HashSet<TrafficFeature>();
            for (FlowEntry flowEntry: flowentrys.get(deviceId)) {
                trafficFeature.add(flowEntryToTrafficFeatue(flowEntry));
            }
            trafficTeatures.put(deviceId, trafficFeature);
        }
        return trafficTeatures;
    }

    // get TrafficFeatures from received flowEntrys by each device
    public Map<DeviceId, Set<TrafficFeature>> getTrafficFeatures() {
        Map<DeviceId, Set<FlowEntry>> flowentrys = getFlowEntrys();
        Map<DeviceId, Set<TrafficFeature>> trafficTeatures = new HashMap<DeviceId, Set<TrafficFeature>>();
        Set<DeviceId> deviceIds = flowentrys.keySet();
        for (DeviceId deviceId: deviceIds) {
            Set<TrafficFeature> trafficFeature = new HashSet<TrafficFeature>();
            for (FlowEntry flowEntry: flowentrys.get(deviceId)) {
                trafficFeature.add(flowEntryToTrafficFeatue(flowEntry));
            }
            trafficTeatures.put(deviceId, trafficFeature);
        }
        return trafficTeatures;
    }

    //Modify  Flow Entry

    //convert flowEntry to TrafficFeatue class
    public TrafficFeature flowEntryToTrafficFeatue(FlowEntry flowEntry) {
        TrafficFeature trafficFeature = new TrafficFeature();
        Set<Criterion> features = flowEntry.selector().criteria();
        for (Criterion feature: features) {
            if (feature.type() == Criterion.Type.IPV4_SRC) {
                IPCriterion ip = (IPCriterion) feature;
                trafficFeature.setSrc((Ip4Prefix) ip.ip());
            }
            if (feature.type() == Criterion.Type.IPV4_DST) {
                IPCriterion ip = (IPCriterion) feature;
                trafficFeature.setDst((Ip4Prefix) ip.ip());
            }
            if (feature.type() == Criterion.Type.IP_PROTO) {
                IPProtocolCriterion ip = (IPProtocolCriterion) feature;
                if (ip.protocol() == IPv4.PROTOCOL_TCP) {
                    trafficFeature.setProtocol("tcp");
                }
                if (ip.protocol() == IPv4.PROTOCOL_UDP) {
                    trafficFeature.setProtocol("udp");
                }
                if (ip.protocol() == IPv4.PROTOCOL_ICMP) {
                    trafficFeature.setProtocol("icmp");
                    trafficFeature.setPort(TpPort.tpPort(0));
                }
            }
            if (feature.type() == Criterion.Type.TCP_DST) {
                TcpPortCriterion tp = (TcpPortCriterion) feature;
                trafficFeature.setPort(tp.tcpPort());
            }
            if (feature.type() == Criterion.Type.UDP_DST) {
                UdpPortCriterion tp = (UdpPortCriterion) feature;
                trafficFeature.setPort(tp.udpPort());
            }
        }
        trafficFeature.setFlowrule(flowEntry);
        return trafficFeature;
    }

    //convert firewall to TrafficFeatue class
    public TrafficFeature firewallEntryToTrafficFeatue(FlowEntry flowEntry) {
        TrafficFeature trafficFeature = new TrafficFeature();
        Set<Criterion> features = flowEntry.selector().criteria();
        for (Criterion feature: features) {
            if (feature.type() == Criterion.Type.IPV4_SRC) {
                IPCriterion ip = (IPCriterion) feature;
                trafficFeature.setSrc((Ip4Prefix) ip.ip());
            }
            if (feature.type() == Criterion.Type.IPV4_DST) {
                IPCriterion ip = (IPCriterion) feature;
                trafficFeature.setDst((Ip4Prefix) ip.ip());
            }
            if (feature.type() == Criterion.Type.IP_PROTO) {
                IPProtocolCriterion ip = (IPProtocolCriterion) feature;
                if (ip.protocol() == IPv4.PROTOCOL_TCP) {
                    trafficFeature.setProtocol("tcp");
                }
                if (ip.protocol() == IPv4.PROTOCOL_UDP) {
                    trafficFeature.setProtocol("udp");
                }
                if (ip.protocol() == IPv4.PROTOCOL_ICMP) {
                    trafficFeature.setProtocol("icmp");
                }
            }
        }
        trafficFeature.setFlowrule(flowEntry);
        return trafficFeature;
    }

    // About FlowEntry

    //get Firewall flowEntrys from a device -2017.6.14
    public Map<DeviceId, Set<FlowEntry>> getFirewalledFlowEntrys(DeviceId deviceId) {
        Map<DeviceId, Set<FlowEntry>> flowentrys = new HashMap<DeviceId, Set<FlowEntry>>();
        Set<FlowEntry> flowentry = new HashSet<FlowEntry>();
        Iterable<FlowEntry> flows = flowRuleService.getFlowEntries(deviceId);
        for (FlowEntry flow : flows) {
            if ( appId.equals(flow.appId())) {
                if (flow.state() == FlowEntry.FlowEntryState.ADDED
                        || flow.state() == FlowEntry.FlowEntryState.PENDING_ADD ) {
                    flowentry.add(flow);
                }

            }
        }
        if (!flowentry.isEmpty()) {
            flowentrys.put(deviceId, flowentry);
        }
        return flowentrys;
    }

    //get flowEntrys from a device
    public Map<DeviceId, Set<FlowEntry>> getFlowEntrys(DeviceId deviceId) {
        Map<DeviceId, Set<FlowEntry>> flowentrys = new HashMap<DeviceId, Set<FlowEntry>>();
        Set<FlowEntry> flowentry = new HashSet<FlowEntry>();
        Iterable<FlowEntry> flows = flowRuleService.getFlowEntries(deviceId);
        log.info("");
        log.info("start! get flows");
        for (FlowEntry flow : flows) {
            if (!flow.isPermanent()) {
                if (!(appId.id() == flow.appId())) {
                    if (flow.state() == FlowEntry.FlowEntryState.ADDED
                            || flow.state() == FlowEntry.FlowEntryState.PENDING_ADD ) {
                        flowentry.add(flow);
                        log.info("flows there");
                    }
                }
            }
        }
        if (!flowentry.isEmpty()) {
            flowentrys.put(deviceId, flowentry);
        }
        log.info("ends!-------------------------------------------------");
        log.info("");
        return flowentrys;
    }
    // get flowEntrys by each devices
    public Map<DeviceId, Set<FlowEntry>> getFlowEntrys() {
        Map<DeviceId, Set<FlowEntry>> flowentrys = new HashMap<DeviceId, Set<FlowEntry>>();

        for (DeviceId deviceId: getDeviceId()) {
            Set<FlowEntry> flowentry = new HashSet<FlowEntry>();
            Iterable<FlowEntry> flows = flowRuleService.getFlowEntries(deviceId);
            for (FlowEntry flow : flows) {
                if (!flow.isPermanent()) {
                    if (!(appId.id() == flow.appId())) {
                        if (flow.state() == FlowEntry.FlowEntryState.ADDED
                                || flow.state() == FlowEntry.FlowEntryState.PENDING_ADD ) {
                            flowentry.add(flow);
                        }
                    }
                }
            }
            if (!flowentry.isEmpty()) {
                flowentrys.put(deviceId, flowentry);
            }
        }
        return flowentrys;
    }

    // About Device(Switch or Routers in Control) id

    // get deviceIds current exists device from topologyService
    public List<DeviceId> getDeviceId() {
        List<DeviceId> devices = new ArrayList<DeviceId>();
        TopologyGraph graph = topologyService.getGraph(topologyService.currentTopology());
        for (TopologyVertex v: graph.getVertexes()) {
            devices.add(v.deviceId());
        }
        return devices;
    }
    // get deviceId from para id
    public DeviceId getDeviceId(String id) {

        return DeviceId.deviceId(id);
    }

    public Schedule buildSchedule() {
        return new Schedule();
    }
    public Schedule buildSchedule(int option) {
        return new Schedule(option);
    }
    public Schedule buildSchedule(int option, String name) {
        return new Schedule(option, name);
    }

    public class Schedule implements Runnable {

        public int option = 0;
        public String name = "test.csv";

        public Schedule() {

        }
        public Schedule(int option) {
            this.option = option;

        }
        public Schedule(int option, String name) {
            this.option = option;
            this.name = name;

        }
        @Override
        public void run() {

            excutes();
        }

        public void excutes() {
            switch (option) {
                case 1:
                    addIns(getInstances("of:0000000000000006"));
                    break;
                case 2:
                    addIns(getInstances());
                    break;
                case 3:
                    block();
                    break;
                case 4:
                    block(1);
                    break;
                default:
                    break;
            }
        }
    }
}