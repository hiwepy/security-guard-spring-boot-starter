package org.springframework.security.boot.antisamy.cache;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.support.ResourcePatternResolver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

@DisplayName("AntiSamyCacheManager Tests")
class AntiSamyCacheManagerTest {

    @Test
    @DisplayName("Instance can be created via getInstance")
    void testInstantiation() {
        PolicyCacheManager pcm = PolicyCacheManager.getInstance(mock(ResourcePatternResolver.class));
        AntiSamyCacheManager instance = AntiSamyCacheManager.getInstance(pcm);
        assertThat(instance).isNotNull();
    }
}
