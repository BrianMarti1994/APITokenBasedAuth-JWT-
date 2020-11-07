using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;

namespace TokenBasedAuth
{
    public class CustomAuthentication : AuthorizationFilterAttribute
    {

        public override void OnAuthorization(HttpActionContext actionContext)
        {
            //Check If headers are not null
            if (actionContext.Request.Headers.Authorization == null)
            {
                actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized);
            }
            else
            {
                //Retrive Headers Information
                AuthenticationHeaderValue authorization  = actionContext.Request.Headers.Authorization;


                //Get Toke Type Provided
                string authorizationType = authorization.Scheme;

                //Get The value provided
                string token = actionContext.Request.Headers.Authorization.Parameter;

                //Check if the provided credentials  are ok
                if (authorizationType != "Bearer" || token == "")
                {
                    actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized, "Unauthorized Token");
                }
                else
                {
                    //Validate Token
                    string response =  TokenManager.ValidateToken(token);
                    if (string.IsNullOrEmpty(response))
                    {
                        actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized, "Unauthorized Token");
                    }
                   
                }

            }
        }
    }
}
