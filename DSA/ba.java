import java.util.Scanner;
class ba{
    public static void main(String[] args) {
        int [][] arr = new int[3][3];
        System.out.println("Enter elements in 2D array");
        Scanner sc = new Scanner(System.in);
        // arr = new int[3][3];


        for(int i=0;i<arr.length;i++){
            for(int j=0;j<arr[i].length;j++){
                arr[i][j] = sc.nextInt();
            }
        }

        for(int i=0;i<arr.length;i++){
            for(int j=0;j<arr[i].length;j++){
                System.out.print(arr[i][j] + " ");
            }
            System.out.println();
        }
}
}