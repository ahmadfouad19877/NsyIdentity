using IdentityServerNSY.Interface;
using IdentityServerNSY.ModelView;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityServerNSY.API
{
    [Route("api")]
    [ApiController]
    [Authorize(Policy = "SuperAdmin")]
    public class ClientIdController : ControllerBase
    {
        private readonly IClientIdRep _clientIdRep;

        public ClientIdController(IClientIdRep clientIdRep)
        {
            _clientIdRep = clientIdRep;
        }
        [HttpPost]
        [Route("AddClient")]
        public async Task<IActionResult> AddClient(ApplicationClientIdView model)
        {
            try
            {
                var data = await _clientIdRep.AddClient(model);
                if (data.Succeeded)
                {
                    return StatusCode(200, new
                    {
                        status = true
                    });
                }
                return StatusCode(402, new
                {
                    status = false,
                    data.Errors
                }); 
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    status = false,
                    result = ex.ToString()
                });
            }
        }
        
        [HttpPost]
        [Route("AddServer")]
        public async Task<IActionResult> AddServer(ApplicationServerClientIdView model)
        {
            try
            {
                var data = await _clientIdRep.AddServer(model);
                if (data.Succeeded)
                {
                    return StatusCode(200, new
                    {
                        status = true
                    });
                }
                return StatusCode(402, new
                {
                    status = false,
                    data.Errors
                }); 
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    status = false,
                    result = ex.ToString()
                });
            }
        }
        
            /// <summary>
        /// إضافة Machine-to-Machine Client
        /// Add machine-to-machine client
        /// </summary>
        /// <param name="request">بيانات العميل المطلوب إضافته / Machine client request</param>
        /// <returns>نتيجة العملية / Operation result</returns>
        [HttpPost("AddMachineClient")]
        public async Task<IActionResult> AddMachineClient([FromBody] ApplicationMachineClientIdView request)
        {
            try
            {
                // التحقق من أن الطلب نفسه غير فارغ
                // Validate that the request itself is not null
                if (request is null)
                {
                    return BadRequest(new
                    {
                        status = false,
                        message = "Request body is required."
                    });
                }

                // التحقق من ClientId
                // Validate client id
                if (string.IsNullOrWhiteSpace(request.clientId))
                {
                    return BadRequest(new
                    {
                        status = false,
                        message = "clientId is required."
                    });
                }

                // التحقق من ClientSecret
                // Validate client secret
                if (string.IsNullOrWhiteSpace(request.clientSecrit))
                {
                    return BadRequest(new
                    {
                        status = false,
                        message = "clientSecrit is required."
                    });
                }

                // التحقق من وجود Scope واحد على الأقل
                // Validate at least one scope exists
                if (request.Scopes is null || !request.Scopes.Any(x => !string.IsNullOrWhiteSpace(x)))
                {
                    return BadRequest(new
                    {
                        status = false,
                        message = "At least one scope is required."
                    });
                }

                // استدعاء المستودع لإضافة العميل
                // Call repository to add the client
                var result = await _clientIdRep.AddMachineClient(request);

                // في حال فشل العملية
                // In case operation fails
                if (!result.Succeeded)
                {
                    return BadRequest(new
                    {
                        status = false,
                        message = "Failed to create machine client.",
                        errors = result.Errors.Select(e => new
                        {
                            code = e.Code,
                            description = e.Description
                        })
                    });
                }

                // نجاح العملية
                // Successful operation
                return Ok(new
                {
                    status = true,
                    message = "Machine client created successfully.",
                    data = new
                    {
                        clientId = request.clientId,
                        displayName = request.DisplayName,
                        scopes = request.Scopes,
                        allowIntrospection = request.AllowIntrospection
                    }
                });
            }
            catch (Exception ex)
            {
                // تسجيل الخطأ وإرجاع 500
                // Log exception and return 500
                return StatusCode(StatusCodes.Status500InternalServerError, new
                {
                    status = false,
                    message = "An unexpected error occurred while creating the machine client.",
                    error = ex.Message
                });
            }
        }
        
        [HttpPost]
        [Route("EditeClientId")]
        public async Task<IActionResult> EditeClient(ApplicationClientIdView model)
        {
            try
            {
                var data = await _clientIdRep.EditeClient(model);
                if (data.Succeeded)
                {
                    return StatusCode(200, new
                    {
                        status = true
                    });
                }
                return StatusCode(402, new
                {
                    status = false,
                    data.Errors
                }); 
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    status = false,
                    result = ex.ToString()
                });
            }
        }
        
        [HttpPost]
        [Route("GetClientId")]
        public async Task<IActionResult> GetClient(RequestIDView model)
        {
            try
            {
                var data = await _clientIdRep.GetClient(model.ClientID);
                return StatusCode(200, new
                {
                    status = true,
                    data
                }); 
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    status = false,
                    result = ex.ToString()
                });
            }
        }
        
        [HttpPost]
        [Route("DeleteClientId")]
        public async Task<IActionResult> DeleteClient(RequestIDView model)
        {
            try
            {
                var data = await _clientIdRep.DeleteClient(model.ClientID);
                if (data.Succeeded)
                {
                    return StatusCode(200, new
                    {
                        status = true
                    });
                }
                return StatusCode(402, new
                {
                    status = false,
                    data.Errors
                }); 
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    status = false,
                    result = ex.ToString()
                });
            }
        }
        
        [HttpGet]
        [Route("ListClientId")]
        public async Task<IActionResult> ListClient()
        {
            try
            {
                var data = await _clientIdRep.ListClient();
                return StatusCode(200, new
                {
                    status = true,
                    data
                }); 
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    status = false,
                    result = ex.ToString()
                });
            }
        }
        
        [HttpGet]
        [Route("ListUserClientId")]
        public async Task<IActionResult> ListClient1()
        {
            try
            {
                var data = await _clientIdRep.ListPublicClients();
                return StatusCode(200, new
                {
                    status = true,
                    data
                }); 
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    status = false,
                    result = ex.ToString()
                });
            }
        }
        [HttpGet]
        [Route("ListServerClientId")]
        public async Task<IActionResult> ListServerClient()
        {
            try
            {
                var data = await _clientIdRep.ListServerClients();
                return StatusCode(200, new
                {
                    status = true,
                    data
                }); 
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    status = false,
                    result = ex.ToString()
                });
            }
        }
        [HttpGet]
        [Route("ListMachineClientId")]
        public async Task<IActionResult> ListMachineClientId()
        {
            try
            {
                var data = await _clientIdRep.ListMachineClients();
                return StatusCode(200, new
                {
                    status = true,
                    data
                }); 
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    status = false,
                    result = ex.ToString()
                });
            }
        }
        
    }
}
