/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2019
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package it.infn.mw.iam.test.registration;

import com.fasterxml.jackson.databind.ObjectMapper;
import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.registration.RegistrationRequestDto;
import it.infn.mw.iam.test.api.TestSupport;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.log;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = {IamLoginService.class, CoreControllerTestSupport.class})
@WebAppConfiguration
@Transactional
public class RegistrationUsernameTests extends TestSupport {
    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    WebApplicationContext context;

    @Autowired
    MockOAuth2Filter oauth2Filter;

    @Autowired
    IamAccountRepository repo;

    private MockMvc mvc;

    @Before
    public void setup() {
        oauth2Filter.cleanupSecurityContext();
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).alwaysDo(log()).build();
    }

    @After
    public void teardown() {
        oauth2Filter.cleanupSecurityContext();
    }

    private RegistrationRequestDto createRegistrationRequest(String username) {

        String email = username + "@example.org";
        RegistrationRequestDto request = new RegistrationRequestDto();
        request.setGivenname("Test");
        request.setFamilyname("User");
        request.setEmail(email);
        request.setUsername(username);
        request.setNotes("Some short notes...");
        request.setPassword("password");

        return request;
    }

    @Test
    public void validUsernames() throws Exception {
        final String[] validUsernames = {"bob", "b", "test$", "root", "test1234", "test_", "_test"};

        for (String u : validUsernames) {
            RegistrationRequestDto r = createRegistrationRequest(u);
            mvc.perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(r))).andExpect(status().isOk());
        }

    }

    @Test
    public void nonUnixUsernames() throws Exception {
        final String[] nonUnixUsernames = {"£$%^&*(", ".,", "-test", "1test", "test$$", "username@example.com", "username@domain",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};

        for (String u : nonUnixUsernames) {
            RegistrationRequestDto r = createRegistrationRequest(u);
            mvc.perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(r))).andExpect(status().isBadRequest());
        }
    }


}