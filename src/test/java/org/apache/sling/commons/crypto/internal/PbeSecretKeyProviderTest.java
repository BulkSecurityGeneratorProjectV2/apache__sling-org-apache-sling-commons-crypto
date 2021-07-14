/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sling.commons.crypto.internal;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.lang3.reflect.FieldUtils;
import org.apache.sling.commons.crypto.PasswordProvider;
import org.apache.sling.commons.crypto.SaltProvider;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class PbeSecretKeyProviderTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void testMissingConfiguration() {
        final PbeSecretKeyProvider provider = new PbeSecretKeyProvider();
        exception.expect(NullPointerException.class);
        exception.expectMessage("Configuration must not be null");
        provider.getSecretKey();
    }

    @Test
    public void testInvalidAlgorithm() throws NoSuchAlgorithmException {
        final PbeSecretKeyProvider provider = new PbeSecretKeyProvider();
        final PbeSecretKeyProviderConfiguration configuration = mock(PbeSecretKeyProviderConfiguration.class);
        when(configuration.algorithm()).thenReturn("Invalid");
        exception.expect(NoSuchAlgorithmException.class);
        provider.activate(configuration);
    }

    @Test
    public void testInvalidKeySpec() throws NoSuchAlgorithmException, IllegalAccessException {
        final PasswordProvider passwordProvider = mock(PasswordProvider.class);
        when(passwordProvider.getPassword()).thenReturn("+AQ?aDes!'DBMkrCi:FE6q\\sOn=Pbmn=PK8n=PK?".toCharArray());
        final SaltProvider saltProvider = mock(SaltProvider.class);
        when(saltProvider.getSalt()).thenReturn("CAFEBABECAFEDEAD".getBytes(StandardCharsets.UTF_8));
        final PbeSecretKeyProvider provider = new PbeSecretKeyProvider();
        FieldUtils.writeDeclaredField(provider, "passwordProvider", passwordProvider, true);
        FieldUtils.writeDeclaredField(provider, "saltProvider", saltProvider, true);

        final PbeSecretKeyProviderConfiguration configuration = mock(PbeSecretKeyProviderConfiguration.class);
        when(configuration.algorithm()).thenReturn("PBKDF2WithHmacSHA1");
        when(configuration.iterationCount()).thenReturn(-1);
        when(configuration.keyLength()).thenReturn(-1);
        provider.activate(configuration);

        exception.expect(IllegalArgumentException.class);
        provider.getSecretKey();
    }

    @Test
    public void testComponentLifecycle() throws NoSuchAlgorithmException, IllegalAccessException {
        final PasswordProvider passwordProvider = mock(PasswordProvider.class);
        when(passwordProvider.getPassword()).thenReturn("+AQ?aDes!'DBMkrCi:FE6q\\sOn=Pbmn=PK8n=PK?".toCharArray());
        final SaltProvider saltProvider = mock(SaltProvider.class);
        when(saltProvider.getSalt()).thenReturn("CAFEBABECAFEDEAD".getBytes(StandardCharsets.UTF_8));
        final PbeSecretKeyProvider provider = new PbeSecretKeyProvider();
        FieldUtils.writeDeclaredField(provider, "passwordProvider", passwordProvider, true);
        FieldUtils.writeDeclaredField(provider, "saltProvider", saltProvider, true);
        { // activate
            final PbeSecretKeyProviderConfiguration configuration = mock(PbeSecretKeyProviderConfiguration.class);
            when(configuration.algorithm()).thenReturn("PBKDF2WithHmacSHA1");
            when(configuration.iterationCount()).thenReturn(1024);
            when(configuration.keyLength()).thenReturn(128);
            provider.activate(configuration);
            assertThat(provider.getSecretKey().getAlgorithm()).isEqualTo("PBKDF2WithHmacSHA1");
        }
        { // modified
            final PbeSecretKeyProviderConfiguration configuration = mock(PbeSecretKeyProviderConfiguration.class);
            when(configuration.algorithm()).thenReturn("PBKDF2WithHmacSHA256");
            when(configuration.iterationCount()).thenReturn(2048);
            when(configuration.keyLength()).thenReturn(256);
            provider.modified(configuration);
            assertThat(provider.getSecretKey().getAlgorithm()).isEqualTo("PBKDF2WithHmacSHA256");
        }
        { // deactivate
            provider.deactivate();
            assertThat(provider.getSecretKey().getAlgorithm()).isEqualTo("PBKDF2WithHmacSHA256");
        }
    }

}