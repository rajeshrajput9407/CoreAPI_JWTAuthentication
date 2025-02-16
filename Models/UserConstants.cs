namespace JWTAuthentication.Models {
    public class UserConstants {
        public static List<UserModel> Users = new()
            {
                    new UserModel(){ Username="rajesh",Password="Demo@123",Role="Admin"}
            };
    }
}
