package it.infn.mw.iam.persistence.model;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

@Entity
@Table(name = "iam_totp_recovery_code")
public class IamTotpRecoveryCode implements Serializable {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "code")
  private String code;

  @ManyToOne(fetch = FetchType.EAGER)
  @JoinColumn(name = "iam_totp_mfa", referencedColumnName = "id", nullable = false)
  private IamTotpMfa totpMfa;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "creationtime", nullable = false)
  private Date creationTime;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "lastupdatetime", nullable = false)
  private Date lastUpdateTime;

  public IamTotpRecoveryCode(String code) {
    this.code = code;
  }

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public IamTotpMfa getTotpMfa() {
    return totpMfa;
  }

  public void setTotpMfa(final IamTotpMfa totpMfa) {
    this.totpMfa = totpMfa;
  }

  public String getCode() {
    return code;
  }

  public void setCode(final String code) {
    this.code = code;
  }

  public Date getCreationTime() {

    return creationTime;
  }

  public void setCreationTime(final Date creationTime) {

    this.creationTime = creationTime;
  }

  public Date getLastUpdateTime() {

    return lastUpdateTime;
  }

  public void setLastUpdateTime(final Date lastUpdateTime) {

    this.lastUpdateTime = lastUpdateTime;
  }

  @Override
  public String toString() {
    return "IamAccount [id=" + id + ", code=" + code + "]";
  }

  @Override
  public boolean equals(final Object obj) {

    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    IamTotpRecoveryCode other = (IamTotpRecoveryCode) obj;
    if (code == null) {
      if (other.code != null)
        return false;
    } else if (!code.equals(other.code))
      return false;
    return true;
  }
}
