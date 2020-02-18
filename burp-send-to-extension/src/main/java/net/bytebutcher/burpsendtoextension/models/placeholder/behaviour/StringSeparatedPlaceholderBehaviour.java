package net.bytebutcher.burpsendtoextension.models.placeholder.behaviour;

public class StringSeparatedPlaceholderBehaviour extends PlaceholderBehaviour {

    private final String separator;

    public StringSeparatedPlaceholderBehaviour(String placeholder, String separator) {
        super(placeholder);
        this.separator = separator;
    }

    public String getSeparator() {
        return separator;
    }
}
