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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.UUID;

import org.apache.commons.lang3.reflect.MethodUtils;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.ops4j.pax.exam.util.PathUtils;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class FilePasswordProviderTest {

    private static final char[] PASSWORD_ASCII = "+AQ?aDes!'DBMkrCi:FE6q\\sOn=Pbmn=PK8n=PK?".toCharArray();

    private static final char[] PASSWORD_ASCII_NEWLINE = "+AQ?aDes!'DBMkrCi:FE6q\\sOn=Pbmn=PK8n=PK?\n".toCharArray();

    private static final char[] PASSWORD_ASCII_NEWLINES = "+AQ?aDes!'DBMkrCi:FE6q\\sOn=Pbmn=PK8n=PK?\n\n".toCharArray();

    private static final char[] PASSWORD_UTF8 = " Napøleøn Sølø (DK) \uD83C\uDFC1\uD83C\uDDE9\uD83C\uDDF0".toCharArray();

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void testMissingConfiguration() {
        final FilePasswordProvider provider = new FilePasswordProvider();
        exception.expect(NullPointerException.class);
        exception.expectMessage("Configuration must not be null");
        provider.getPassword();
    }

    @Test
    public void testComponentLifecycle() throws Exception {
        final FilePasswordProvider provider = new FilePasswordProvider();
        { // activate
            final String path = String.format("%s/src/test/resources/password.ascii85", PathUtils.getBaseDir());
            final FilePasswordProviderConfiguration configuration = mock(FilePasswordProviderConfiguration.class);
            when(configuration.path()).thenReturn(path);
            MethodUtils.invokeMethod(provider, true, "activate", configuration);
            assertThat(provider.getPassword(), is(PASSWORD_ASCII));
        }
        { // modified
            final String path = String.format("%s/src/test/resources/password.utf8", PathUtils.getBaseDir());
            final FilePasswordProviderConfiguration configuration = mock(FilePasswordProviderConfiguration.class);
            when(configuration.path()).thenReturn(path);
            MethodUtils.invokeMethod(provider, true, "modified", configuration);
            assertThat(provider.getPassword(), is(PASSWORD_UTF8));
        }
        { // deactivate
            MethodUtils.invokeMethod(provider, true, "deactivate");
            assertThat(provider.getPassword(), is(PASSWORD_UTF8));
        }
    }

    @Test
    public void testPasswordFile() throws Exception {
        final FilePasswordProvider provider = new FilePasswordProvider();
        final String path = String.format("%s/src/test/resources/password.ascii85", PathUtils.getBaseDir());
        final FilePasswordProviderConfiguration configuration = mock(FilePasswordProviderConfiguration.class);
        when(configuration.path()).thenReturn(path);
        when(configuration.fix_posixNewline()).thenReturn(false);
        MethodUtils.invokeMethod(provider, true, "activate", configuration);
        assertThat(provider.getPassword(), is(PASSWORD_ASCII));
        // enable fix for POSIX newline
        when(configuration.fix_posixNewline()).thenReturn(true);
        MethodUtils.invokeMethod(provider, true, "modified", configuration);
        assertThat(provider.getPassword(), is(PASSWORD_ASCII));
    }

    @Test
    public void testPasswordFileWithNewline() throws Exception {
        final FilePasswordProvider provider = new FilePasswordProvider();
        final String path = String.format("%s/src/test/resources/password.ascii85_newline", PathUtils.getBaseDir());
        final FilePasswordProviderConfiguration configuration = mock(FilePasswordProviderConfiguration.class);
        when(configuration.path()).thenReturn(path);
        when(configuration.fix_posixNewline()).thenReturn(false);
        MethodUtils.invokeMethod(provider, true, "activate", configuration);
        assertThat(provider.getPassword(), is(PASSWORD_ASCII_NEWLINE));
        // enable fix for POSIX newline
        when(configuration.fix_posixNewline()).thenReturn(true);
        MethodUtils.invokeMethod(provider, true, "modified", configuration);
        assertThat(provider.getPassword(), is(PASSWORD_ASCII));
    }

    @Test
    public void testPasswordFileWithNewlines() throws Exception {
        final FilePasswordProvider provider = new FilePasswordProvider();
        final String path = String.format("%s/src/test/resources/password.ascii85_newlines", PathUtils.getBaseDir());
        final FilePasswordProviderConfiguration configuration = mock(FilePasswordProviderConfiguration.class);
        when(configuration.path()).thenReturn(path);
        when(configuration.fix_posixNewline()).thenReturn(false);
        MethodUtils.invokeMethod(provider, true, "activate", configuration);
        assertThat(provider.getPassword(), is(PASSWORD_ASCII_NEWLINES));
        // enable fix for POSIX newline
        when(configuration.fix_posixNewline()).thenReturn(true);
        MethodUtils.invokeMethod(provider, true, "modified", configuration);
        assertThat(provider.getPassword(), is(PASSWORD_ASCII_NEWLINE));
    }

    @Test
    public void testPasswordFileNotReadableDuringConfigurationCheck() throws Exception {
        final FilePasswordProvider provider = new FilePasswordProvider();
        final String path = String.format("%s%s", System.getProperty("java.io.tmpdir"), UUID.randomUUID());
        final FilePasswordProviderConfiguration configuration = mock(FilePasswordProviderConfiguration.class);
        when(configuration.path()).thenReturn(path);
        when(configuration.fix_posixNewline()).thenReturn(false);
        exception.expectCause(instanceOf(IOException.class));
        // no way to check message of *cause*?
        // final String message = String.format("Unable to read password file '%s'", path);
        // exception.expectMessage(message);
        MethodUtils.invokeMethod(provider, true, "activate", configuration);
    }

    @Test
    public void testPasswordFileNotReadableAfterConfigurationCheck() throws Exception {
        final FilePasswordProvider provider = new FilePasswordProvider();
        final File file = Files.createTempFile(UUID.randomUUID().toString(), null).toFile();
        final String path = file.getPath();
        final FilePasswordProviderConfiguration configuration = mock(FilePasswordProviderConfiguration.class);
        when(configuration.path()).thenReturn(path);
        when(configuration.fix_posixNewline()).thenReturn(false);
        MethodUtils.invokeMethod(provider, true, "activate", configuration);
        file.delete();
        exception.expect(RuntimeException.class);
        final String message = String.format("Unable to read password file '%s'", path);
        exception.expectMessage(message);
        provider.getPassword();
    }

}
