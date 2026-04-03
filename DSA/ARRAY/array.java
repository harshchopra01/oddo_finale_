import java.util.*;

class array{
public static void main(String[] args) {
    int[] arr = new int[5];
    Scanner sc = new Scanner(System.in);

    System.out.println("Enter integers:");
    for(int i=0;i<arr.length;i++){
        arr[i] = sc.nextInt();
    }
    reverse(arr);
}

public static void display(int[] arr){
    System.out.println("Reversed array:");
    for(int i=0;i<arr.length;i++){
        System.out.println(arr[i]);
    }
}

public  static void reverse(int [] arr) {
    int i = 0;
    int j = arr.length - 1;
    while (i<j) { 
        int temp = arr[i];
        arr[i] = arr[j];
        arr[j] = temp;
        i++;
        j--;
    }  
display(arr);
}

}
