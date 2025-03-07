package com.utilities;

import  java.util.ArrayList;
import java.util.Arrays;

public class InvalidIndexParametersException extends Exception {


    ArrayList<String> indexes;

    public InvalidIndexParametersException(String message) {
        super(message);
    }
    
    public InvalidIndexParametersException(String message, String... Idx) {
        super(message);
        this.indexes = new ArrayList<String>(Arrays.asList(Idx)); // Directly convert array to list
    }

    @Override
    public String getMessage() {
        return super.getMessage();
    }

    public ArrayList<String> getIndexes() {
        return this.indexes;
    }
    public void setIndexes(ArrayList<String> indexes) {
        this.indexes = indexes;
    }

    public String printMessageWithIndexes() {
        return getMessage() + "\n" + String.join(", ", getIndexes());
    }

}