package burp;

import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class BurpExtender implements IBurpExtender, ITab, ISessionHandlingAction, IExtensionStateListener {
    private static final String extName = "BurpKit";
    private IBurpExtenderCallbacks callback = null;
    private IExtensionHelpers helper = null;
    private BurpKitTab tab;

    private static String extVersion;

    static {
        try {
            Properties prop = new Properties();
            prop.load(BurpExtender.class.getClassLoader().getResourceAsStream("burpkit.properties"));
            extVersion = prop.getProperty("burpkit.version");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        callback = iBurpExtenderCallbacks;
        helper = callback.getHelpers();

        callback.setExtensionName(extName);
        callback.registerSessionHandlingAction(this);
        callback.registerExtensionStateListener(this);

        SwingUtilities.invokeLater(() -> {
            tab = new BurpKitTab();

            if (callback.loadExtensionSetting("BURPKIT_NEW") != null) {
                // Restore settings.
                for (int i = 0; i < tab.headerActions.length; i++) {
                    tab.headerActions[i].setSelectedItem(callback.loadExtensionSetting("HEADER_ACTION_" + i));
                    tab.headerNames[i].setText(callback.loadExtensionSetting("HEADER_NAME_" + i));
                    tab.headerPrefixes[i].setText(callback.loadExtensionSetting("HEADER_PREFIX_" + i));
                    tab.headerValues[i].setText(callback.loadExtensionSetting("HEADER_VALUE_" + i));
                    tab.regexpCheckBoxes[i].setSelected(Boolean.parseBoolean(callback.loadExtensionSetting("HEADER_REGEXP_" + i)));
                }
            }

            callback.customizeUiComponent(tab.mainPanel);
            callback.addSuiteTab(BurpExtender.this);
        });

        callback.printOutput(extName + " " + extVersion + " extension loaded.");
    }

    @Override
    public String getActionName() {
        return extName;
    }

    @Override
    public void performAction(IHttpRequestResponse currentRequest, IHttpRequestResponse[] macroItems) {
        IRequestInfo requestInfo = helper.analyzeRequest(currentRequest);
        ArrayList<String> headers = (ArrayList<String>) requestInfo.getHeaders();
        Iterator<String> headerIter = headers.iterator();

        for (int i = 0; i < tab.headerActions.length; i++) {
            switch (String.valueOf(tab.headerActions[i].getSelectedItem())) {
                case "Add Header":
                    String newHeader;
                    String newValue = tab.headerValues[i].getText();

                    if (tab.regexpCheckBoxes[i].isSelected()) {
                        Pattern p;
                        try {
                            p = Pattern.compile(tab.headerValues[i].getText());
                        } catch (PatternSyntaxException e) {
                            callback.printError(e.toString());
                            return;
                        }

                        if (macroItems.length == 0) {
                            callback.printError("Macro returns empty.");
                            return;
                        }

                        for (IHttpRequestResponse macroItem : macroItems) {
                            byte[] macroResponse = macroItem.getResponse();
                            Matcher m = p.matcher(helper.bytesToString(macroResponse));
                            if (m.find() && m.group(1).length() > 0) {
                                newValue = m.group(1);
                                break;
                            }
                        }

                        if (newValue.equals(tab.headerValues[i].getText())) {
                            callback.printError("Regexp not matched.");
                        }
                    }

                    while (headerIter.hasNext()) {
                        String header = headerIter.next();
                        if (header.startsWith(tab.headerNames[i].getText())) {
                            headerIter.remove();
                        }
                    }

                    newHeader = tab.headerNames[i].getText() + ": " + tab.headerPrefixes[i].getText() + newValue;
                    headers.add(newHeader);
                    callback.printOutput("Updated header: " + newHeader);
                    break;
                case "Remove Header":
                    String removedHeader = tab.headerNames[i].getText();
                    while (headerIter.hasNext()) {
                        String header = headerIter.next();
                        if (header.startsWith(removedHeader)) {
                            headerIter.remove();
                        }
                    }
                    callback.printOutput("Removed header: " + removedHeader);

                    break;
                case "Disabled":
//                    callback.printOutput("Action" + i + " Disabled");
                    break;
                default:
                    callback.printError("Internal Error.");
            }
        }

        // Customize headers.
        byte[] newHttpMessage = helper.buildHttpMessage(headers, Arrays.copyOfRange(currentRequest.getRequest(), requestInfo.getBodyOffset(), currentRequest.getRequest().length));
        currentRequest.setRequest(newHttpMessage);
    }

    @Override
    public String getTabCaption() {
        return extName;
    }

    @Override
    public Component getUiComponent() {
        return tab.mainPanel;
    }

    @Override
    public void extensionUnloaded() {
        // Save settings.
        callback.saveExtensionSetting("BURPKIT_NEW", "FALSE");
        for (int i = 0; i < tab.headerActions.length; i++) {
            callback.saveExtensionSetting("HEADER_ACTION_" + i, (String) tab.headerActions[i].getSelectedItem());
            callback.saveExtensionSetting("HEADER_NAME_" + i, tab.headerNames[i].getText());
            callback.saveExtensionSetting("HEADER_PREFIX_" + i, tab.headerPrefixes[i].getText());
            callback.saveExtensionSetting("HEADER_VALUE_" + i, tab.headerValues[i].getText());
            callback.saveExtensionSetting("HEADER_REGEXP_" + i, String.valueOf(tab.regexpCheckBoxes[i].isSelected()));
        }

        callback.printOutput(extName + " extension unloaded.");
    }
}
