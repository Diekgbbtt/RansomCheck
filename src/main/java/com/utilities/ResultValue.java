package com.utilities;

import java.util.*;




public class ResultValue {

    private String key;

    private HashMap<String, String> values;
    private HashMap<String, String> values_expected;

    public ResultValue(String key, HashMap<String, String> values, HashMap<String, String> values_expected) {
        this.key = key;
        this.values = values;
        this.values_expected = values_expected;
    }

    public ResultValue(String key) {
        this.key = key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getKey() {
        return key;
    }

    public void setValues(HashMap<String, String> values) {
        this.values = values;
    }

    public HashMap<String, String> getValues() {
        return this.values;
    }

    public void setValuesExp(HashMap<String, String> values_expected) {
        this.values_expected = values_expected;
    }

    public HashMap<String, String> getValuesExp() {
        return this.values_expected;
    }

    public void result_check() {
        List<String> warn_list = new ArrayList<String>();
        for (String key : values.keySet()) {
            if(values_expected.get(key) != values.get(key)) {
                warn_list.add(key);
            }
        }
        if(warn_list.size() > 0) {
            // email or external warn 
            String Warn = " Warning : "+warn_list.size()+" discrepancies revealed : \n";
            for ( String key : warn_list) {
                Warn += ""+key+" : "+values.get(key)+" values found while expected value is : "+values_expected.get(key)+"\n";
            }
            System.out.println(Warn);
        } else {
            System.out.println("No attacck revealed");
        }
    }






}