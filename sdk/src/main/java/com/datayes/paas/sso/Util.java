package com.datayes.paas.sso;

import javax.servlet.ServletConfig;
import java.util.Random;

public class Util {


    public static String getConfiguration(ServletConfig servletConfig, String configuration) {
        return servletConfig.getInitParameter(configuration);
    }
}
