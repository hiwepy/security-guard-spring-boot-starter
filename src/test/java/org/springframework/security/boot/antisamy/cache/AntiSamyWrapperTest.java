package org.springframework.security.boot.antisamy.cache;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.owasp.validator.html.AntiSamy;
import org.owasp.validator.html.Policy;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("AntiSamyWrapper Tests")
class AntiSamyWrapperTest {

    @Test
    @DisplayName("Instance can be created via constructor")
    void testInstantiation() {
        AntiSamyWrapper instance = new AntiSamyWrapper(null, null, 1, null);
        assertThat(instance).isNotNull();
    }

    @Test
    @DisplayName("Getters and setters work")
    void testGettersSetters() {
        AntiSamyWrapper wrapper = new AntiSamyWrapper(null, null, 1, new String[]{"X-Test"});
        assertThat(wrapper.getAntiSamy()).isNull();
        assertThat(wrapper.getPolicy()).isNull();
        assertThat(wrapper.getScanType()).isEqualTo(1);
        assertThat(wrapper.getPolicyHeaders()).containsExactly("X-Test");

        wrapper.setScanType(0);
        assertThat(wrapper.getScanType()).isEqualTo(0);
        wrapper.setPolicyHeaders(new String[]{"X-Custom"});
        assertThat(wrapper.getPolicyHeaders()).containsExactly("X-Custom");
    }
}
