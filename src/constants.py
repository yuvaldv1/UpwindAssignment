# the query to the provider, can be changed according to needs
GITHUB_QUERY = """
    {
      securityVulnerabilities(first: 100, ecosystem: %s, package: "%s") {

      nodes {
        severity
        package {
          name
          ecosystem
        }
        vulnerableVersionRange
        firstPatchedVersion{
            identifier  
      }

      }
    }
    }
    """