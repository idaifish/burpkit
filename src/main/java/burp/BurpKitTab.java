package burp;

import javax.swing.*;

public class BurpKitTab {

    protected JTabbedPane tabbedPane;
    protected JPanel mainPanel;
    protected JPanel customizeHeaderPanel;
    protected JLabel action1Label;
    protected JComboBox action1;
    protected JLabel header1Label;
    protected JTextField header1Name;
    protected JTextField header1Value;
    protected JCheckBox regExpCheckBox1;
    protected JTextField header1Prefix;
    protected JComboBox action2;
    protected JTextField header2Name;
    protected JTextField header2Prefix;
    protected JTextField header2Value;
    protected JCheckBox regExpCheckBox2;
    protected JComboBox action3;
    protected JTextField header3Name;
    protected JTextField header3Prefix;
    protected JTextField header3Value;
    protected JLabel header2Label;
    protected JLabel header3Label;
    protected JLabel action2Label;
    protected JLabel action3Label;
    protected JCheckBox regExpCheckBox3;

    protected JComboBox[] headerActions = {action1, action2, action3};
    protected JTextField[] headerNames = {header1Name, header2Name, header3Name};
    protected JTextField[] headerPrefixes = {header1Prefix, header2Prefix, header3Prefix};
    protected JTextField[] headerValues = {header1Value, header2Value, header3Value};
    protected JCheckBox[] regexpCheckBoxes = {regExpCheckBox1, regExpCheckBox2, regExpCheckBox3};
}
