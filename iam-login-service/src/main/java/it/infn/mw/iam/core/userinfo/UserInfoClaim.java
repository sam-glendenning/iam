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
package it.infn.mw.iam.core.userinfo;

public enum UserInfoClaim {
  ATTR,
  SUB,
  NAME,
  PREFERRED_USERNAME,
  GIVEN_NAME,
  FAMILY_NAME,
  MIDDLE_NAME,
  NICKNAME,
  PROFILE,
  PICTURE,
  WEBSITE,
  GENDER,
  ZONEINFO,
  LOCALE,
  UPDATED_AT,
  BIRTHDATE,
  EMAIL,
  EMAIL_VERIFIED,
  PHONE_NUMBER,
  PHONE_NUMBER_VERIFIED,
  ADDRESS,
  ORGANISATION_NAME,
  GROUPS,
  EXTERNAL_AUTHN,
  EDUPERSON_SCOPED_AFFILIATION,
  EDUPERSON_ENTITLEMENT,
  SSH_KEYS;
}
