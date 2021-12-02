/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021
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
package it.infn.mw.iam.persistence.model;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.persistence.OneToOne;
import javax.persistence.Table;

@Entity
@Table(name = "iam_totp_mfa")
public class IamTotpMfa implements Serializable {

  private static final long serialVersionUID = 1L;

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false, length = 36, unique = true)
  private String uuid;

  @OneToOne()
  private IamAccount account;

  @Column(name = "secret")
  private String secret;

  @Column(name = "active", nullable = false)
  private boolean active;

  @OneToMany(mappedBy = "totpMfa", cascade = CascadeType.ALL, fetch = FetchType.EAGER,
      orphanRemoval = true)
  private Set<IamTotpRecoveryCode> recoveryCodes = new HashSet<>();

  public IamTotpMfa() {}

  public IamTotpMfa(IamAccount account) {
    this.account = account;
  }

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public String getUuid() {
    return uuid;
  }

  public void setUuid(final String uuid) {
    this.uuid = uuid;
  }

  public IamAccount getAccount() {
    return account;
  }

  public void setAccount(final IamAccount account) {
    this.account = account;
  }

  public String getSecret() {
    return secret;
  }

  public void setSecret(final String secret) {
    this.secret = secret;
  }

  public boolean isActive() {

    return active;
  }

  public void setActive(final boolean active) {

    this.active = active;
  }

  public Set<IamTotpRecoveryCode> getRecoveryCodes() {
    return recoveryCodes;
  }

  public void setRecoveryCodes(final Set<IamTotpRecoveryCode> recoveryCodes) {
    if (this.recoveryCodes.isEmpty()) {
      this.recoveryCodes = recoveryCodes;
    } else {
      this.recoveryCodes.clear();
      this.recoveryCodes.addAll(recoveryCodes);
    }
  }

  public void regenerateRecoveryCodes() {
    // TODO
  }

  @Override
  public String toString() {
    return "IamTotpMfa [active=" + active + ", id=" + id + ", secret=" + secret + ", uuid=" + uuid
        + "]";
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((uuid == null) ? 0 : uuid.hashCode());
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    IamTotpMfa other = (IamTotpMfa) obj;
    if (uuid == null) {
      if (other.uuid != null)
        return false;
    } else if (!uuid.equals(other.uuid))
      return false;
    return true;
  }
}
