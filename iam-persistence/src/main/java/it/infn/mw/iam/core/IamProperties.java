package it.infn.mw.iam.core;

public enum IamProperties {

  INSTANCE;

  private String organisationName;

  private IamProperties() {

  }

  public String getOrganisationName() {

    return organisationName;
  }

  public void setOrganisationName(String organisationName) {

    this.organisationName = organisationName;
  }

}
