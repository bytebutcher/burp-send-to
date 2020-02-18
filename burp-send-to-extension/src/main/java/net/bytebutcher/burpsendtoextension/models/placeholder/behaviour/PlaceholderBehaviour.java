package net.bytebutcher.burpsendtoextension.models.placeholder.behaviour;

import java.util.Objects;

public abstract class PlaceholderBehaviour {

    private final String placeholder;

    public PlaceholderBehaviour(String placeholder) {
        this.placeholder = placeholder;
    }

    public String getPlaceholder() {
        return placeholder;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || !(o instanceof PlaceholderBehaviour)) return false;
        PlaceholderBehaviour that = (PlaceholderBehaviour) o;
        return placeholder.equals(that.placeholder);
    }

    @Override
    public int hashCode() {
        return Objects.hash(placeholder);
    }
}
