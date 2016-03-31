package it.infn.security.openam.aggregator;

import java.util.HashMap;
import java.util.Map;

import com.sun.identity.shared.debug.Debug;

public class AggrConfigurationFactory {

    private static Map<String, AggrConfiguration> theConfiguration = new HashMap<String, AggrConfiguration>();

    public static synchronized AggrConfiguration getInstance(String realm)
        throws AggregatorException {

        if (realm == null) {
            realm = "";
        } else {
            realm = realm.trim();
        }

        if (!theConfiguration.containsKey(realm)) {

            try {

                String confClassName = System.getProperty("it.infn.security.openam.agid.configuration.class",
                        "it.infn.security.openam.agid.AgIDAggrConfiguration");
                AggrConfiguration tmpConf = (AggrConfiguration) Class.forName(confClassName).newInstance();

                tmpConf.init(realm);
                theConfiguration.put(realm, tmpConf);

            } catch (Throwable th) {
                Debug.getInstance("Aggregator").error(th.getMessage(), th);
                throw new AggregatorException(th.getMessage());
            }

        }

        return theConfiguration.get(realm);
    }
}