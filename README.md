## EPS ROTATION KEY AGENT

Rotate your AWS credentials stored in your EPS secret manager account.

#### ABSTRACT

> Changing access keys (which consist of an access key ID and a secret access key) on a regular schedule is a 
well-known security best practice because it shortens the period an access key is active and therefore reduces 
the business impact if they are compromised. 

> Having an established process that is run regularly also ensures the operational steps around key rotation are 
verified, so changing a key is never a scary step. [more ...](https://aws.amazon.com/blogs/security/how-to-rotate-access-keys-for-iam-users/)


#### INSTALLATION

> Python 3 is required.

> You have to register the follwing environment variables.

  ```
  export EPS_USER_NAME="EPS login user"
  export EPS_USER_PASSWORD="EPS password"
  ```

Next install required packages from requirements.txt file.

  ```bash
  pip install -r requirements.txt
  ```

#### USAGE

```sh
python main.py \
--url https://:your_eps_hostname_server/SecretServer/webservices/SSwebservice.asmx\?WSDL \
--domain :your_domain
```

> Notice you have to change :your_eps_hostname_server for the name of the EPS server you are using.
> Also make sure you have to change :your_domain for the domain name configured in your EPS server.

#### VERSION

1.0.0 Initial
1.1.0 EPS secret manager support

#### CONTACT

[Jaziel Lopez, Software Engineer](mailto: juan.jaziel@gmail.com)

