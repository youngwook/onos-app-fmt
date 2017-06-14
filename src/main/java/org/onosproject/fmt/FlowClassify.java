package org.onosproject.fmt;


import org.osgi.service.component.ComponentContext;
import weka.classifiers.Classifier;
import weka.classifiers.meta.Vote;
import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.FastVector;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.SelectedTag;
import weka.core.SerializationHelper;
import weka.core.converters.ArffLoader;
import weka.core.converters.ConverterUtils;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Created by root on 16. 11. 9.
 */
public class FlowClassify implements FlowFeatures {

    public static final String MODEL_PATH = "model/";

    public static final String ARFF_PATH = "data/";

    public static final String ARFF_OUT_PATH = System.getProperty("user.home") + "/data/";

    public static Classifier classifier = null;

    public static List<Classifier> classifiers = new ArrayList<Classifier>();

    public static Instances instances = null;

    public void init() {


    }

    public double classify(Classifier classifier, Instance instance) {
        try {
            return classifier.classifyInstance(instance);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return 0;
    }
    public double classify(Vote classifier, Instance instance) {
        try {
            return classifier.classifyInstance(instance);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return 0;
    }

    public void writeArffFiles(Instances instances, String name) {

        BufferedWriter saver;

        try {
            File file = new File(ARFF_OUT_PATH);
            if (!file.exists()) {
                file.mkdir();
            }
            saver = new BufferedWriter(new FileWriter(ARFF_OUT_PATH + name));
            saver.write(instances.toString());
            saver.flush();
            saver.close();
        } catch (IOException e) {
            e.printStackTrace();
        }


    }

    public Vote getClassifiers() {
        List<Classifier> classifiers = new ArrayList<Classifier>();
        for (Model name : Model.values()) {
            classifiers.add(readModel(name.getModel()));
        }
        Vote clf = new Vote();
        SelectedTag tag = new SelectedTag(Vote.MAJORITY_VOTING_RULE, Vote.TAGS_RULES);
        clf.setCombinationRule(tag);
        Classifier[] models = new Classifier[classifiers.size()];
        clf.setClassifiers(classifiers.toArray(models));
        return clf;
    }

    public Classifier getClassifier() {

        return readModel(Model.RBF.getModel());

    }

    public Classifier getClassifier(int i) {

        return readModel(Model.MLP.getModel());

    }

    public Instances getInstances(List<Map<TrafficFeature, List<String>>> flowfeatures) {

        Instances instances = createAttributes();
        instances.setClassIndex(instances.numAttributes() - 1);

        for (Map<TrafficFeature, List<String>> features : flowfeatures) {
            Set<TrafficFeature> feature = features.keySet();
            for (TrafficFeature tf: feature) {
                List<String> values = features.get(tf);
                Instance instance = new DenseInstance(instances.numAttributes());
                for (int i = 0; i < values.size(); i++) {
                    if (instances.attribute(i).isNominal()) {
                        instance.setValue(instances.attribute(i), values.get(i));
                    } else {
                        instance.setValue(instances.attribute(i), Double.valueOf(values.get(i)));
                    }
                }
                instance.setMissing(instances.numAttributes() - 1);
                instances.add(instance);
            }
        }

        return instances;
    }
    public Instances getInstances(Map<TrafficFeature, List<String>> flowfeatures) {

        Instances instances = createAttributes();
        instances.setClassIndex(instances.numAttributes() - 1);


        Set<TrafficFeature> feature = flowfeatures.keySet();
        for (TrafficFeature tf: feature) {
            List<String> values = flowfeatures.get(tf);
            Instance instance = new DenseInstance(instances.numAttributes());
            for (int i = 0; i < values.size(); i++) {
                if (instances.attribute(i).isNominal()) {
                    instance.setValue(instances.attribute(i), values.get(i));
                } else {
                    instance.setValue(instances.attribute(i), Double.valueOf(values.get(i)));
                }
            }
            instance.setMissing(instances.numAttributes() - 1);
            instances.add(instance);
        }

        return instances;
    }
    public Instances createAttributes() {
        FastVector attributes = new FastVector();
        for (Attributes at : Attributes.values()) {
            Attribute attribute;
            if (at.getAttribute().equals("protocol_type")) {
                FastVector f = new FastVector(3);
                f.addElement("tcp");
                f.addElement("udp");
                f.addElement("icmp");
                attribute = new Attribute(at.getAttribute(), f);
            } else if (at.getAttribute().equals("attack")) {
                FastVector f = new FastVector(2);
                f.addElement("normal.");
                f.addElement("abnormal.");
                attribute = new Attribute(at.getAttribute(), f);
            } else {
                attribute = new Attribute(at.getAttribute());
            }
            attributes.addElement(attribute);
        }

        return new Instances("flows", attributes, 0);
    }



    public Classifier readModel(String name) {
        InputStream file = new java.io.BufferedInputStream(getClass().getClassLoader().getResourceAsStream(MODEL_PATH + name));

        Classifier model = null;
        try {

            model = (Classifier) SerializationHelper.read(file);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return model;
    }
    public Instances readFile(String name) {


        ClassLoader loader = getClass().getClassLoader();
        URL path = loader.getResource(ARFF_PATH + name);
        Instances data = null;
        try {
            ArffLoader source = new ArffLoader();
            source.setSource(path);
            data = source.getDataSet();
            data.setClassIndex(data.numAttributes() - 1);
            return data;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return data;
    }
}

