﻿using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;


namespace identity_trial3.Models
{
    public class UsuarioRegistro
    {
        public required string NombreUsuario { get; set; }
        public required string Correo { get; set; }
        public required string Clave { get; set; }
        public required string TipoUsuario { get; set; }
    }
}
