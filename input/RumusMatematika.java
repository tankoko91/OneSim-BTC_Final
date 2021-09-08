/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package input;

/**
 *
 * @author WINDOWS_X
 */
public class RumusMatematika {

    public RumusMatematika() {
    }
    
    public float bagi(double a, double b){
        return (float) (a/b);
    }
    
    public float kali(double a, double b){
        return (float) (a*b);
    }
    
    public float kurang(float a, float b){
        return (a-b);
    }
    
    public float bulat(float a, int b){
        float bulat = (float) Math.round(a*Math.pow(10, b))/(float) Math.pow(10, b);
        return bulat;
    }
}
