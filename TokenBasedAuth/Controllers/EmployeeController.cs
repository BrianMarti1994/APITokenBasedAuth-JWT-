using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;

using System.Web.Http;

namespace TokenBasedAuth.Controllers
{
    public class EmployeeController : ApiController
    {


      
        [HttpGet]
        public HttpResponseMessage ValidateLogin(string userName ,string password)
        {

            //If the Provided User Credentials are correct  we will Send user a Token

            if (userName == "CodeBrian" && password == "brian123")
            {
                return Request.CreateResponse(HttpStatusCode.OK, value: TokenManager.GenerateToken(userName));
            }
            else
            {
                return Request.CreateResponse(HttpStatusCode.NotFound, "Invalid User Credentials");
            }
        }

        [CustomAuthentication]
        [HttpGet]
        public HttpResponseMessage GetEmployee()
        {

            return Request.CreateResponse(HttpStatusCode.OK, "Brian");
        }
    }


   

}
